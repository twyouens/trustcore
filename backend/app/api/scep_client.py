"""
SCEP Client Endpoints - app/api/scep_clients.py
REST API endpoints for managing SCEP clients
"""
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.schemas.scep_client import (
    SCEPClientCreate,
    SCEPClientResponse,
    SCEPClientUpdate,
    SCEPClientStats
)
from app.services.scep_client_service import scep_client_service
from app.services.audit_service import audit_service
from app.services.auth_service import get_current_admin, get_current_user

router = APIRouter(prefix="/scep/clients", tags=["SCEP Management"])


@router.post("",
    response_model=SCEPClientResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create SCEP Client",
    description="Register a new SCEP client (MDM system). Requires admin role.")
async def create_scep_client(
    client_data: SCEPClientCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Create a new SCEP client
    
    **Only admins can create SCEP clients.**
    
    A SCEP client represents an MDM or automated system that can request
    certificates via the SCEP protocol. Each client gets a unique SCEP URL.
    
    Returns:
        SCEPClientResponse with SCEP URL
    """
    # Create client
    scep_client = scep_client_service.create_client(
        db=db,
        name=client_data.name,
        description=client_data.description,
        allowed_certificate_types=client_data.allowed_certificate_types,
        user_validation_url=client_data.user_validation_url,
        machine_validation_url=client_data.machine_validation_url,
        enabled=client_data.enabled,
        created_by_id=current_user.id
    )
    
    # Reload with relationships
    scep_client = scep_client_service.get_client_by_id(db, scep_client.id)
    
    # Audit log
    audit_service.log_scep_client_created(
        db=db,
        user=current_user,
        client_id=scep_client.id,
        ip_address=None,
        allowed_certificate_types=scep_client.allowed_certificate_types,
        client_name=scep_client.name
    )
    
    return scep_client


@router.get("",
    response_model=List[SCEPClientResponse],
    summary="List SCEP Clients",
    description="List all SCEP clients. Requires admin role.")
async def list_scep_clients(
    include_disabled: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    List all SCEP clients
    
    **Only admins can view SCEP clients.**
    
    Args:
        include_disabled: Include disabled clients
    
    Returns:
        List of SCEP clients
    """
    clients = scep_client_service.get_all_clients(db, include_disabled=include_disabled)
    return clients


@router.get("/stats",
    response_model=List[SCEPClientStats],
    summary="Get SCEP Client Statistics",
    description="Get usage statistics for all SCEP clients. Requires admin role.")
async def get_scep_client_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Get SCEP client statistics
    
    **Only admins can view statistics.**
    
    Returns:
        List of client statistics including success rates
    """
    stats = scep_client_service.get_client_stats(db)
    return stats


@router.get("/{client_id}",
    response_model=SCEPClientResponse,
    summary="Get SCEP Client",
    description="Get SCEP client details by ID. Requires admin role.")
async def get_scep_client(
    client_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Get SCEP client details
    
    **Only admins can view SCEP clients.**
    
    Returns:
        SCEP client details including SCEP URL
    """
    scep_client = scep_client_service.get_client_by_id(db, client_id)
    
    if not scep_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SCEP client not found"
        )
    
    return scep_client


@router.patch("/{client_id}",
    response_model=SCEPClientResponse,
    summary="Update SCEP Client",
    description="Update SCEP client details. Requires admin role.")
async def update_scep_client(
    client_id: UUID,
    client_data: SCEPClientUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Update SCEP client
    
    **Only admins can update SCEP clients.**
    
    You can update the client's name, description, allowed certificate types,
    validation URLs, or enable/disable the client.
    
    Returns:
        Updated SCEP client
    """
    updated_client = scep_client_service.update_client(
        db=db,
        client_id=client_id,
        name=client_data.name,
        description=client_data.description,
        allowed_certificate_types=client_data.allowed_certificate_types,
        user_validation_url=client_data.user_validation_url,
        machine_validation_url=client_data.machine_validation_url,
        enabled=client_data.enabled
    )
    
    if not updated_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SCEP client not found"
        )
    
    # Reload with relationships
    updated_client = scep_client_service.get_client_by_id(db, client_id)
    
    # Audit log
    audit_service.log_scep_client_updated(
        db=db,
        user=current_user,
        client_id=client_id,
        changes=client_data.model_dump(exclude_unset=True)
    )

    return updated_client


@router.delete("/{client_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete SCEP Client",
    description="Delete a SCEP client. Requires admin role.")
async def delete_scep_client(
    client_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Delete a SCEP client
    
    **Only admins can delete SCEP clients.**
    
    This will permanently delete the client and prevent any further
    certificate requests using this client's SCEP URL.
    
    Returns:
        204 No Content on success
    """
    # Get client for audit log before deletion
    scep_client = scep_client_service.get_client_by_id(db, client_id)
    
    if not scep_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SCEP client not found"
        )
    
    client_name = scep_client.name
    
    # Delete client
    deleted = scep_client_service.delete_client(db, client_id)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SCEP client not found"
        )
    
    # Audit log
    audit_service.log_scep_client_deleted(
        db=db,
        user=current_user,
        client_id=client_id,
        client_name=client_name
    )
    
    return None


@router.post("/{client_id}/disable",
    response_model=SCEPClientResponse,
    summary="Disable SCEP Client",
    description="Disable a SCEP client. Requires admin role.")
async def disable_scep_client(
    client_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Disable a SCEP client
    
    **Only admins can disable SCEP clients.**
    
    Disabling a client will immediately prevent any new certificate requests
    using this client's SCEP URL.
    
    Returns:
        Updated SCEP client
    """
    updated_client = scep_client_service.update_client(
        db=db,
        client_id=client_id,
        enabled=False
    )
    
    if not updated_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SCEP client not found"
        )
    
    # Reload with relationships
    updated_client = scep_client_service.get_client_by_id(db, client_id)
    
    # Audit log
    audit_service.log_scep_client_disabled(
        db=db,
        user=current_user,
        client_id=client_id
    )

    return updated_client


@router.post("/{client_id}/enable",
    response_model=SCEPClientResponse,
    summary="Enable SCEP Client",
    description="Enable a SCEP client. Requires admin role.")
async def enable_scep_client(
    client_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Enable a SCEP client
    
    **Only admins can enable SCEP clients.**
    
    Enabling a client will allow certificate requests using this client's SCEP URL.
    
    Returns:
        Updated SCEP client
    """
    updated_client = scep_client_service.update_client(
        db=db,
        client_id=client_id,
        enabled=True
    )
    
    if not updated_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SCEP client not found"
        )
    
    # Reload with relationships
    updated_client = scep_client_service.get_client_by_id(db, client_id)
    
    # Audit log
    audit_service.log_scep_client_enabled(
        db=db,
        user=current_user,
        client_id=client_id
    )

    return updated_client