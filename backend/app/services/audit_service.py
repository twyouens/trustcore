from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from app.models.audit import AuditLog
from app.models.user import User
import json


class AuditService:
    @staticmethod
    def log(
        db: Session,
        action: str,
        resource_type: str,
        resource_id: Optional[int] = None,
        user: Optional[User] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        """Create an audit log entry"""
        audit_log = AuditLog(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user.id if user else None,
            details=json.dumps(details) if details else None,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        db.add(audit_log)
        db.commit()
        db.refresh(audit_log)
        
        return audit_log
    
    @staticmethod
    def log_certificate_request(
        db: Session,
        certificate_id: int,
        certificate_type: str,
        user: User,
        ip_address: Optional[str] = None,
    ):
        """Log certificate request"""
        return AuditService.log(
            db=db,
            action="certificate_requested",
            resource_type="certificate",
            resource_id=certificate_id,
            user=user,
            details={"certificate_type": certificate_type},
            ip_address=ip_address,
        )
    
    @staticmethod
    def log_certificate_approval(
        db: Session,
        certificate_id: int,
        admin: User,
        approved: bool,
        ip_address: Optional[str] = None,
    ):
        """Log certificate approval/rejection"""
        action = "certificate_approved" if approved else "certificate_rejected"
        return AuditService.log(
            db=db,
            action=action,
            resource_type="certificate",
            resource_id=certificate_id,
            user=admin,
            ip_address=ip_address,
        )
    
    @staticmethod
    def log_certificate_revocation(
        db: Session,
        certificate_id: int,
        admin: User,
        reason: str,
        ip_address: Optional[str] = None,
    ):
        """Log certificate revocation"""
        return AuditService.log(
            db=db,
            action="certificate_revoked",
            resource_type="certificate",
            resource_id=certificate_id,
            user=admin,
            details={"reason": reason},
            ip_address=ip_address,
        )
    
    @staticmethod
    def log_certificate_download(
        db: Session,
        certificate_id: int,
        user: User,
        ip_address: Optional[str] = None,
    ):
        """Log certificate download"""
        return AuditService.log(
            db=db,
            action="certificate_downloaded",
            resource_type="certificate",
            resource_id=certificate_id,
            user=user,
            ip_address=ip_address,
        )
    
    @staticmethod
    def log_user_login(
        db: Session,
        user: User,
        ip_address: Optional[str] = None,
    ):
        """Log user login"""
        return AuditService.log(
            db=db,
            action="user_login",
            resource_type="user",
            resource_id=user.id,
            user=user,
            ip_address=ip_address,
        )


audit_service = AuditService()