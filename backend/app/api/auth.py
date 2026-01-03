from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.user import Token, UserResponse, AuthorizationRedirect
from app.schemas.api_token import TokenLoginResponse, TokenLoginRequest
from app.services.auth_service import auth_service, get_current_user
from app.services.audit_service import audit_service
from app.services.api_token_service import api_token_service
from app.models.user import User
from datetime import timedelta, datetime
from app.core.config import settings
from app.core.logging import get_logger

router = APIRouter(prefix="/auth", tags=["authentication"])

logger = get_logger(__name__)


@router.get("/login", response_model=AuthorizationRedirect)
def login():
    """
    Get OIDC authorization URL
    Frontend should redirect user to this URL
    """
    authorization_url = auth_service.get_authorization_url()
    
    if not authorization_url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate authorization URL",
        )
    return AuthorizationRedirect(redirect_uri=authorization_url)



@router.post("/callback", response_model=Token)
def callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db),
):
    """
    Handle OIDC callback
    Exchange authorization code for access token
    """
    try:
        # Exchange code for token and get user info from ID token
        userinfo = auth_service.exchange_code_for_token(code, state)
        
        if not userinfo:
            logger.error(f"Authentication error: Invalid or expired state")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: Invalid or expired state",
            )
        
        # Get or create user (JIT provisioning)
        user = auth_service.get_or_create_user(userinfo, db)
        
        # Create our own JWT token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = auth_service.create_access_token(
            data={"sub": user.username, "role": user.role.value},
            expires_delta=access_token_expires,
        )
        
        # Audit log
        audit_service.log_user_login(db=db, user=user)
        
        return {"access_token": access_token, "token_type": "bearer"}
        
    except ValueError as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authentication failed: Bad Request",
        )
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: Internal Server Error",
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
):
    """Get current authenticated user information"""
    return current_user


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
):
    """
    Logout (client should discard token)
    This endpoint exists for consistency but JWT tokens can't be invalidated server-side
    """
    return {"message": "Logged out successfully"}

@router.post("/token/login", response_model=TokenLoginResponse)
async def token_login(
    request: TokenLoginRequest,
    db: Session = Depends(get_db)
):
    """
    Exchange API token for JWT
    
    This endpoint allows automation scripts to exchange their API token
    for a short-lived JWT token that can be used for subsequent API requests.
    
    Flow:
    1. Script provides API token
    2. Server validates token and returns JWT
    3. Script uses JWT for API calls (same as OIDC flow)
    4. JWT expires after configured time (default 30 minutes)
    5. Script exchanges API token again for new JWT
    
    Args:
        request: TokenLoginRequest with api_token
    
    Returns:
        TokenLoginResponse with JWT access token
    """
    # Authenticate the API token
    user = api_token_service.authenticate_token(db, request.api_token)
    
    if not user:
        # Log failed authentication attempt
        audit_service.log_api_token_login_failed(
            db=db,
            user=None,
            ip_address=None,
            reason="Invalid or expired API token"
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API token"
        )
    
    # Check if user is active
    if not user.is_active:
        audit_service.log_api_token_login_failed(
            db=db,
            user=user,
            ip_address=None,
            reason="User account is inactive"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    # Create JWT access token (same as OIDC flow)
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth_service.create_access_token(
        data={"sub": user.email, "role": user.role.value},
        expires_delta=access_token_expires
    )
    
    # Update user's last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Audit log
    audit_service.log
    
    return TokenLoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user
    )
    