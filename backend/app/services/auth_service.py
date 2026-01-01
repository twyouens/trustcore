from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.user import TokenData
from app.core.oauth_client import OAuthClient

security = HTTPBearer()


class AuthService:
    def __init__(self):
        self.oauth_client = OAuthClient(
            issuer=settings.OIDC_ISSUER,
            client_id=settings.OIDC_CLIENT_ID,
            client_secret=settings.OIDC_CLIENT_SECRET,
            redirect_uri=settings.OIDC_REDIRECT_URI,
            scope=settings.OIDC_SCOPE,
        )
    
    def get_authorization_url(self) -> Optional[str]:
        """Get OIDC authorization URL"""
        return self.oauth_client.authorize_redirect()
    
    def exchange_code_for_token(self, code: str, state: str) -> Optional[Dict[str, Any]]:
        """
        Exchange authorization code for tokens and extract user info from ID token
        
        Args:
            code: Authorization code from callback
            state: State parameter from callback
            
        Returns:
            User info extracted from ID token claims, or None on failure
        """
        # Exchange code for tokens and validate ID token
        token_data, claims = self.oauth_client.fetch_token(code, state)
        
        if not token_data or not claims:
            return None
        
        # Extract user info from ID token claims
        user_info = self.oauth_client.extract_user_info(claims)
        
        return user_info
    
    def create_access_token(
        self,
        data: dict,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(
            to_encode,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
        
        return encoded_jwt
    
    def decode_token(self, token: str) -> TokenData:
        """Decode and validate JWT token"""
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
            username: str = payload.get("sub")
            role: str = payload.get("role")
            
            if username is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials",
                )
            
            return TokenData(username=username, role=UserRole(role) if role else None)
            
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
    
    def get_or_create_user(
        self,
        userinfo: Dict[str, Any],
        db: Session
    ) -> User:
        """Get existing user or create new user (JIT provisioning)"""
        oidc_subject = userinfo.get(settings.OIDC_USER_KEY)

        if not oidc_subject:
            raise ValueError(f"Missing '{settings.OIDC_USER_KEY}' claim in user info")

        # Try to find existing user
        user = db.query(User).filter(User.username == oidc_subject).first()

        if user:
            # Update last login
            user.last_login = datetime.now()
            # Update other fields from userinfo if present
            user.email = userinfo.get("email", user.email)
            user.full_name = userinfo.get("name", user.full_name)
            # Update role if user is in admin group
            if self.user_in_admin_group(userinfo):
                user.role = UserRole.ADMIN
            else:
                user.role = UserRole.USER
            db.commit()
            db.refresh(user)
            return user
        
        # Create new user (JIT provisioning)
        email = userinfo.get("email")
        if not email:
            raise ValueError("Missing 'email' claim in user info")
        username = oidc_subject
        full_name = userinfo.get("name")
        user_role = UserRole.ADMIN if self.user_in_admin_group(userinfo) else UserRole.USER

        user = User(
            email=email,
            username=username,
            full_name=full_name,
            role=user_role,
            is_active=True,
            last_login=datetime.now(),
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        return user
    
    def user_in_admin_group(self, userinfo: Dict[str, Any]) -> bool:
        """Check if user is in admin group"""
        return userinfo.get("groups") and settings.OIDC_ADMIN_GROUP in userinfo["groups"]


auth_service = AuthService()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Dependency to get current authenticated user"""
    token = credentials.credentials
    token_data = auth_service.decode_token(token)
    
    user = db.query(User).filter(User.username == token_data.username).first()
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    
    return user


async def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """Dependency to require admin role"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user
