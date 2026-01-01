from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.user import Token, UserResponse
from app.services.auth_service import auth_service, get_current_user
from app.services.audit_service import audit_service
from app.models.user import User
from datetime import timedelta
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/login")
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
    
    return {"authorization_url": authorization_url}


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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authentication failed: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: {str(e)}",
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