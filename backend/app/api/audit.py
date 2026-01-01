from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional
from app.core.database import get_db
from app.schemas.audit import AuditLogResponse, AuditLogListResponse
from app.models.audit import AuditLog
from app.models.user import User
from app.services.auth_service import get_current_admin
import json

router = APIRouter(prefix="/audit", tags=["audit-logs"])


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_admin),  # Only admins can view audit logs
    db: Session = Depends(get_db),
):
    """
    List audit logs
    Requires admin role
    """
    query = db.query(AuditLog)
    
    # Apply filters
    if action:
        query = query.filter(AuditLog.action == action)
    
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    logs = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()
    
    # Parse JSON details
    items = []
    for log in logs:
        log_dict = {
            "id": log.id,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "user_id": log.user_id,
            "details": json.loads(log.details) if log.details else None,
            "ip_address": log.ip_address,
            "created_at": log.created_at,
        }
        items.append(AuditLogResponse(**log_dict))
    
    return AuditLogListResponse(
        total=total,
        items=items,
    )