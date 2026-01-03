"""
API Token Service - app/services/api_token_service.py
Business logic for API token management
"""
import secrets
import json
from datetime import datetime, timedelta
from typing import Optional, List, Tuple
import logging

from passlib.context import CryptContext
from sqlalchemy.orm import Session, joinedload

from app.models.api_token import APIToken
from app.models.user import User
from app.core.config import settings

logger = logging.getLogger(__name__)

# Password hashing context for tokens
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class APITokenService:
    """Service for managing API tokens"""
    
    TOKEN_PREFIX = "tca_"  # TrustCore API token prefix
    TOKEN_LENGTH = 64  # Length of random part (hex characters)
    
    @staticmethod
    def generate_token() -> str:
        """
        Generate a cryptographically secure API token
        
        Returns:
            Token string with prefix (e.g., "tca_abc123...")
        """
        random_part = secrets.token_hex(APITokenService.TOKEN_LENGTH // 2)
        return f"{APITokenService.TOKEN_PREFIX}{random_part}"
    
    @staticmethod
    def hash_token(token: str) -> str:
        """
        Hash an API token using bcrypt
        
        Args:
            token: Plaintext token
            
        Returns:
            Bcrypt hash of token
        """
        return pwd_context.hash(token)
    
    @staticmethod
    def verify_token(token: str, token_hash: str) -> bool:
        """
        Verify a token against its hash
        
        Args:
            token: Plaintext token
            token_hash: Bcrypt hash
            
        Returns:
            True if token matches hash
        """
        return pwd_context.verify(token, token_hash)
    
    @staticmethod
    def create_token(
        db: Session,
        user_id: int,
        name: str,
        description: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        expires_in_days: Optional[int] = None
    ) -> Tuple[APIToken, str]:
        """
        Create a new API token
        
        Args:
            db: Database session
            user_id: ID of user creating the token
            name: Human-readable token name
            description: Optional description
            scopes: Optional list of permission scopes
            expires_in_days: Optional expiry in days
            
        Returns:
            Tuple of (APIToken object, plaintext_token)
        """
        # Generate token
        plaintext_token = APITokenService.generate_token()
        token_hash = APITokenService.hash_token(plaintext_token)
        
        # Calculate expiry
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        # Serialize scopes to JSON
        scopes_json = json.dumps(scopes) if scopes else None
        
        # Create token record
        api_token = APIToken(
            name=name,
            description=description,
            token_hash=token_hash,
            user_id=user_id,
            scopes=scopes_json,
            expires_at=expires_at,
            is_active=True
        )
        
        db.add(api_token)
        db.commit()
        db.refresh(api_token)
        
        logger.info(f"Created API token '{name}' for user {user_id}")
        
        return api_token, plaintext_token
    
    @staticmethod
    def get_token_by_id(db: Session, token_id: int) -> Optional[APIToken]:
        """
        Get API token by ID with relationships loaded
        
        Args:
            db: Database session
            token_id: Token ID
            
        Returns:
            APIToken object or None
        """
        return db.query(APIToken).options(
            joinedload(APIToken.user),
            joinedload(APIToken.revoked_by)
        ).filter(APIToken.id == token_id).first()
    
    @staticmethod
    def get_tokens_by_user(
        db: Session,
        user_id: int,
        include_inactive: bool = False
    ) -> List[APIToken]:
        """
        Get all API tokens for a user
        
        Args:
            db: Database session
            user_id: User ID
            include_inactive: Include revoked/inactive tokens
            
        Returns:
            List of APIToken objects
        """
        query = db.query(APIToken).options(
            joinedload(APIToken.user),
            joinedload(APIToken.revoked_by)
        ).filter(APIToken.user_id == user_id)
        
        if not include_inactive:
            query = query.filter(APIToken.is_active == True)
        
        return query.order_by(APIToken.created_at.desc()).all()
    
    @staticmethod
    def get_all_tokens(
        db: Session,
        include_inactive: bool = False
    ) -> List[APIToken]:
        """
        Get all API tokens (admin only)
        
        Args:
            db: Database session
            include_inactive: Include revoked/inactive tokens
            
        Returns:
            List of APIToken objects
        """
        query = db.query(APIToken).options(
            joinedload(APIToken.user),
            joinedload(APIToken.revoked_by)
        )
        
        if not include_inactive:
            query = query.filter(APIToken.is_active == True)
        
        return query.order_by(APIToken.created_at.desc()).all()
    
    @staticmethod
    def authenticate_token(db: Session, token: str) -> Optional[User]:
        """
        Authenticate an API token and return the associated user
        
        Args:
            db: Database session
            token: Plaintext API token
            
        Returns:
            User object if token is valid, None otherwise
        """
        # Get all active tokens (we need to check hashes)
        active_tokens = db.query(APIToken).options(
            joinedload(APIToken.user)
        ).filter(
            APIToken.is_active == True
        ).all()
        
        for api_token in active_tokens:
            # Check if token matches
            if APITokenService.verify_token(token, api_token.token_hash):
                # Check if token is expired
                if api_token.expires_at and api_token.expires_at < datetime.utcnow():
                    logger.warning(f"API token {api_token.id} is expired")
                    return None
                
                # Update last used timestamp
                api_token.last_used_at = datetime.utcnow()
                db.commit()
                
                logger.info(f"API token {api_token.id} authenticated for user {api_token.user_id}")
                return api_token.user
        
        logger.warning("Invalid API token provided")
        return None
    
    @staticmethod
    def revoke_token(
        db: Session,
        token_id: int,
        revoked_by_id: int
    ) -> Optional[APIToken]:
        """
        Revoke an API token
        
        Args:
            db: Database session
            token_id: Token ID to revoke
            revoked_by_id: User ID performing the revocation
            
        Returns:
            Revoked APIToken object or None if not found
        """
        api_token = db.query(APIToken).filter(APIToken.id == token_id).first()
        
        if not api_token:
            return None
        
        api_token.is_active = False
        api_token.revoked_at = datetime.utcnow()
        api_token.revoked_by_id = revoked_by_id
        
        db.commit()
        db.refresh(api_token)
        
        logger.info(f"Revoked API token {token_id} by user {revoked_by_id}")
        
        return api_token
    
    @staticmethod
    def update_token(
        db: Session,
        token_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        is_active: Optional[bool] = None
    ) -> Optional[APIToken]:
        """
        Update an API token
        
        Args:
            db: Database session
            token_id: Token ID
            name: New name (optional)
            description: New description (optional)
            scopes: New scopes (optional)
            is_active: New active status (optional)
            
        Returns:
            Updated APIToken object or None if not found
        """
        api_token = db.query(APIToken).filter(APIToken.id == token_id).first()
        
        if not api_token:
            return None
        
        if name is not None:
            api_token.name = name
        if description is not None:
            api_token.description = description
        if scopes is not None:
            api_token.scopes = json.dumps(scopes)
        if is_active is not None:
            api_token.is_active = is_active
        
        db.commit()
        db.refresh(api_token)
        
        logger.info(f"Updated API token {token_id}")
        
        return api_token
    
api_token_service = APITokenService()