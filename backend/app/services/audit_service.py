from uuid import UUID
from datetime import datetime
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any, Sequence, List
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
        comment: Optional[str] = None
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
            details={"comment": comment} if comment else None,
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
    
    @staticmethod
    def log_ocsp_request(
        db: Session,
        user: User,
        ip_address: Optional[str] = None,
        request_size: int = 0,
        response_size: int = 0
    ):
        """Log OCSP request"""
        return AuditService.log(
            db=db,
            action="ocsp_request",
            resource_type="ocsp",
            resource_id=None,
            user=user,
            ip_address=ip_address,
            details={
                "request_size": request_size,
                "response_size": response_size
            }
        )
    
    @staticmethod
    def log_api_token_created(
        db: Session,
        token_id: int,
        user: User,
        name: str,
        scopes: List[str],
        expires_at: Optional[datetime] = None,
        ip_address: Optional[str] = None,
    ):
        """Log API token creation"""
        return AuditService.log(
            db=db,
            action="api_token_created",
            resource_type="api_token",
            resource_id=token_id,
            user=user,
            ip_address=ip_address,
            details={"name": name, "scopes": scopes, "expires_at": expires_at}
        )

    @staticmethod
    def log_api_token_revoked(
        db: Session,
        token_id: int,
        user: User,
        ip_address: Optional[str] = None,
    ):
        """Log API token revocation"""
        return AuditService.log(
            db=db,
            action="api_token_revoked",
            resource_type="api_token",
            resource_id=token_id,
            user=user,
            ip_address=ip_address
        )

    @staticmethod
    def log_api_token_updated(
        db: Session,
        token_id: int,
        user: User,
        changes: dict,
        ip_address: Optional[str] = None,
    ):
        """Log API token update"""
        return AuditService.log(
            db=db,
            action="api_token_updated",
            resource_type="api_token",
            resource_id=token_id,
            user=user,
            ip_address=ip_address,
            details={"changes": changes}
        )
    
    @staticmethod
    def log_api_token_login_failed(
        db: Session,
        user: Optional[User],
        ip_address: Optional[str] = None,
        reason: str = "Unknown"
    ):
        """Log API token login failure"""
        return AuditService.log(
            db=db,
            action="api_token_login_failed",
            resource_type="token_login",
            resource_id=None,
            user=user,
            ip_address=ip_address,
            details={"reason": reason}
        )

    @staticmethod
    def log_api_token_login_success(
        db: Session,
        user: User,
        token_id: int,
        ip_address: Optional[str] = None
    ):
        """Log API token login success"""
        return AuditService.log(
            db=db,
            action="api_token_login_success",
            resource_type="token_login",
            resource_id=token_id,
            user=user,
            ip_address=ip_address
        )
    
    @staticmethod
    def log_scep_client_created(
        db: Session,
        user: User,
        client_id: UUID,
        client_name: str,
        allowed_certificate_types: Sequence[str],
        ip_address: Optional[str] = None
    ):
        """Log SCEP client creation"""
        return AuditService.log(
            db=db,
            action="scep_client_created",
            resource_type="scep_client",
            resource_id=client_id,
            user=user,
            ip_address=ip_address,
            details={
                "client_name": client_name,
                "allowed_certificate_types": allowed_certificate_types
            }
        )
    
    @staticmethod
    def log_scep_client_updated(
        db: Session,
        user: User,
        client_id: UUID,
        changes: dict,
        ip_address: Optional[str] = None
    ):
        """Log SCEP client update"""
        return AuditService.log(
            db=db,
            action="scep_client_updated",
            resource_type="scep_client",
            resource_id=client_id,
            user=user,
            ip_address=ip_address,
            details={
                "changes": changes
            }
        )

    @staticmethod
    def log_scep_client_deleted(
        db: Session,
        user: User,
        client_id: UUID,
        client_name: str,
        ip_address: Optional[str] = None
    ):
        """Log SCEP client deletion"""
        return AuditService.log(
            db=db,
            action="scep_client_deleted",
            resource_type="scep_client",
            resource_id=client_id,
            user=user,
            ip_address=ip_address,
            details={
                "client_name": client_name
            }
        )

    @staticmethod
    def log_scep_client_disabled(
        db: Session,
        user: User,
        client_id: UUID,
        ip_address: Optional[str] = None
    ):
        """Log SCEP client disabled"""
        return AuditService.log(
            db=db,
            action="scep_client_disabled",
            resource_type="scep_client",
            resource_id=client_id,
            user=user,
            ip_address=ip_address
        )
    
    @staticmethod
    def log_scep_client_enabled(
        db: Session,
        user: User,
        client_id: UUID,
        ip_address: Optional[str] = None
    ):
        """Log SCEP client enabled"""
        return AuditService.log(
            db=db,
            action="scep_client_enabled",
            resource_type="scep_client",
            resource_id=client_id,
            user=user,
            ip_address=ip_address
        )


audit_service = AuditService()