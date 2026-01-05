"""
API Token Endpoints - app/api/api_tokens.py
REST API endpoints for managing API tokens
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.api_token import (
    APITokenCreate,
    APITokenCreated,
    APITokenResponse,
    APITokenUpdate
)
from app.services.api_token_service import APITokenService
from app.services.audit_service import audit_service
from app.services.auth_service import get_current_user, get_current_admin

router = APIRouter(prefix="/tokens", tags=["API Tokens"])


@router.post("",
    response_model=APITokenCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create API Token",
    description="Create a new API token for automation. Requires admin role.")
async def create_api_token(
    token_data: APITokenCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Create a new API token
    
    **Only admins can create API tokens.**
    
    The token will be returned once and cannot be retrieved again.
    Store it securely.
    
    Returns:
        APITokenCreated with plaintext token
    """
    # Create token
    api_token, plaintext_token = APITokenService.create_token(
        db=db,
        user_id=current_user.id,
        name=token_data.name,
        description=token_data.description,
        scopes=token_data.scopes,
        expires_in_days=token_data.expires_in_days
    )
    
    # Reload with relationships
    api_token = APITokenService.get_token_by_id(db, api_token.id)
    
    # Audit log
    audit_service.log_api_token_created(
        db=db,
        token_id=api_token.id,
        user=current_user,
        ip_address=None,
        name=api_token.name,
        scopes=api_token.scopes.split(",") if api_token.scopes else [],
    )

    # Convert to response with plaintext token
    response = APITokenCreated(
        id=api_token.id,
        name=api_token.name,
        description=api_token.description,
        token=plaintext_token,
        scopes=token_data.scopes,
        expires_at=api_token.expires_at,
        created_at=api_token.created_at,
        created_by=api_token.user
    )
    
    return response


@router.get("",
    response_model=List[APITokenResponse],
    summary="List API Tokens",
    description="List API tokens. Admins see all tokens, users see only their own.")
async def list_api_tokens(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List API tokens
    
    - **Admins**: See all tokens
    - **Users**: See only their own tokens
    
    Args:
        include_inactive: Include revoked/inactive tokens
    
    Returns:
        List of API tokens
    """
    if current_user.role == UserRole.ADMIN:
        # Admin sees all tokens
        tokens = APITokenService.get_all_tokens(db, include_inactive=include_inactive)
    else:
        # User sees only their own tokens
        tokens = APITokenService.get_tokens_by_user(
            db, 
            user_id=current_user.id,
            include_inactive=include_inactive
        )
    
    return tokens


@router.get("/{token_id}",
    response_model=APITokenResponse,
    summary="Get API Token",
    description="Get API token details by ID.")
async def get_api_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get API token details
    
    Users can only view their own tokens unless they are admins.
    
    Returns:
        API token details (without plaintext token)
    """
    api_token = APITokenService.get_token_by_id(db, token_id)
    
    if not api_token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API token not found"
        )
    
    # Check permissions
    if current_user.role != UserRole.ADMIN and api_token.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own API tokens"
        )
    
    return api_token


@router.patch("/{token_id}",
    response_model=APITokenResponse,
    summary="Update API Token",
    description="Update API token details.")
async def update_api_token(
    token_id: int,
    token_data: APITokenUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update API token
    
    Users can only update their own tokens unless they are admins.
    Cannot update the token itself, only metadata.
    
    Returns:
        Updated API token
    """
    api_token = APITokenService.get_token_by_id(db, token_id)
    
    if not api_token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API token not found"
        )
    
    # Check permissions
    if current_user.role != UserRole.ADMIN and api_token.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only update your own API tokens"
        )
    
    # Update token
    updated_token = APITokenService.update_token(
        db=db,
        token_id=token_id,
        name=token_data.name,
        description=token_data.description,
        scopes=token_data.scopes,
        is_active=token_data.is_active
    )
    
    # Reload with relationships
    updated_token = APITokenService.get_token_by_id(db, token_id)
    
    # Audit log
    audit_service.log_api_token_updated(
        db=db,
        token_id=token_id,
        user=current_user,
        ip_address=None,
        changes=token_data.model_dump(exclude_unset=True)
    )

    return updated_token


@router.delete("/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke API Token",
    description="Revoke an API token (soft delete).")
async def revoke_api_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Revoke an API token
    
    Users can only revoke their own tokens unless they are admins.
    Revoked tokens cannot be reactivated.
    
    Returns:
        204 No Content on success
    """
    api_token = APITokenService.get_token_by_id(db, token_id)
    
    if not api_token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API token not found"
        )
    
    # Check permissions
    if current_user.role != UserRole.ADMIN and api_token.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only revoke your own API tokens"
        )
    
    # Revoke token
    APITokenService.revoke_token(
        db=db,
        token_id=token_id,
        revoked_by_id=current_user.id
    )
    
    # Audit log
    audit_service.log_api_token_revoked(
        db=db,
        token_id=token_id,
        user=current_user,
        ip_address=None
    )
    
    return None