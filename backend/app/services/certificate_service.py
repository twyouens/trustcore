from sqlalchemy.orm import Session
from typing import Optional, List, Tuple
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app.models.certificate import Certificate, CertificateType, CertificateStatus
from app.models.user import User
from app.services.ca_service import ca_service
from app.services.audit_service import audit_service
from sqlalchemy.orm import joinedload
from app.core.logging import get_logger
import json

logger = get_logger(__name__)

class CertificateService:
    @staticmethod
    def request_machine_certificate(
        db: Session,
        mac_address: str,
        validity_days: int,
        user: User,
        auto_approve: bool = True,
    ) -> Tuple[Certificate, Optional[str]]:
        """
        Request a machine certificate
        Returns: (certificate_record, private_key_pem or None)
        """
        # Generate certificate immediately if auto-approved
        private_key_pem = None
        cert_pem = None
        serial_number = None
        not_before = None
        not_after = None
        status = CertificateStatus.APPROVED if auto_approve else CertificateStatus.PENDING
        
        if auto_approve:
            private_key_pem, cert_pem = ca_service.generate_machine_certificate(
                mac_address=mac_address,
                validity_days=validity_days
            )
            
            # Extract serial number and validity from generated certificate
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            serial_number = str(cert_obj.serial_number)
            not_before = cert_obj.not_valid_before_utc
            not_after = cert_obj.not_valid_after_utc
        else:
            # Generate a temporary serial number for pending certificates
            serial_number = f"PENDING-{datetime.utcnow().timestamp()}"
        
        # Create certificate record
        certificate = Certificate(
            serial_number=serial_number,
            certificate_type=CertificateType.MACHINE,
            common_name=mac_address,
            status=status,
            certificate=cert_pem,
            validity_days=validity_days,
            not_before=not_before,
            not_after=not_after,
            requested_by_id=user.id,
            auto_approved=auto_approve,
        )
        
        if auto_approve:
            certificate.approved_by_id = user.id
            certificate.approved_at = datetime.utcnow()
        
        db.add(certificate)
        db.commit()
        db.refresh(certificate)
        
        # Audit log
        audit_service.log_certificate_request(
            db=db,
            certificate_id=certificate.id,
            certificate_type=CertificateType.MACHINE.value,
            user=user,
        )
        
        if auto_approve:
            audit_service.log_certificate_approval(
                db=db,
                certificate_id=certificate.id,
                admin=user,
                approved=True,
            )
        
        return certificate, private_key_pem
    
    @staticmethod
    def request_user_certificate(
        db: Session,
        username: str,
        validity_days: int,
        user: User,
        auto_approve: bool = True,
    ) -> Tuple[Certificate, Optional[str]]:
        """
        Request a user certificate
        Returns: (certificate_record, private_key_pem or None)
        """
        # Generate certificate immediately if auto-approved
        private_key_pem = None
        cert_pem = None
        serial_number = None
        not_before = None
        not_after = None
        status = CertificateStatus.APPROVED if auto_approve else CertificateStatus.PENDING
        
        if auto_approve:
            private_key_pem, cert_pem = ca_service.generate_user_certificate(
                username=username,
                validity_days=validity_days
            )
            
            # Extract serial number and validity from generated certificate
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            serial_number = str(cert_obj.serial_number)
            not_before = cert_obj.not_valid_before_utc
            not_after = cert_obj.not_valid_after_utc
        else:
            serial_number = f"PENDING-{datetime.utcnow().timestamp()}"
        
        # Create certificate record
        certificate = Certificate(
            serial_number=serial_number,
            certificate_type=CertificateType.USER,
            common_name=username,
            status=status,
            certificate=cert_pem,
            validity_days=validity_days,
            not_before=not_before,
            not_after=not_after,
            requested_by_id=user.id,
            auto_approved=auto_approve,
        )
        
        if auto_approve:
            certificate.approved_by_id = user.id
            certificate.approved_at = datetime.utcnow()
        
        db.add(certificate)
        db.commit()
        db.refresh(certificate)
        
        # Audit log
        audit_service.log_certificate_request(
            db=db,
            certificate_id=certificate.id,
            certificate_type=CertificateType.USER.value,
            user=user,
        )
        
        if auto_approve:
            audit_service.log_certificate_approval(
                db=db,
                certificate_id=certificate.id,
                admin=user,
                approved=True,
            )
        
        return certificate, private_key_pem
    
    @staticmethod
    def request_server_certificate(
        db: Session,
        csr_pem: str,
        validity_days: int,
        user: User,
    ) -> Certificate:
        """
        Request a server certificate (requires approval)
        """
        # Validate CSR
        is_valid, error_msg, sans = ca_service.validate_csr(csr_pem)
        if not is_valid:
            raise ValueError(f"Invalid CSR: {error_msg}")
        
        # Load CSR to extract common name
        csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        common_name = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        
        # Create certificate record
        certificate = Certificate(
            serial_number=f"PENDING-{datetime.utcnow().timestamp()}",
            certificate_type=CertificateType.SERVER,
            common_name=common_name,
            subject_alternative_names=json.dumps(sans) if sans else None,
            status=CertificateStatus.PENDING,
            csr=csr_pem,
            validity_days=validity_days,
            requested_by_id=user.id,
            auto_approved=False,
        )
        
        db.add(certificate)
        db.commit()
        db.refresh(certificate)
        
        # Audit log
        audit_service.log_certificate_request(
            db=db,
            certificate_id=certificate.id,
            certificate_type=CertificateType.SERVER.value,
            user=user,
        )
        
        return certificate
    
    @staticmethod
    def approve_certificate(
        db: Session,
        certificate_id: int,
        admin: User,
    ) -> Certificate:
        """Approve a pending certificate"""
        certificate = db.query(Certificate).filter(Certificate.id == certificate_id).first()
        
        if not certificate:
            raise ValueError("Certificate not found")
        
        if certificate.status != CertificateStatus.PENDING:
            logger.error(f"Certificate is not pending: {certificate.id}")
            raise ValueError("Certificate is not pending")
        
        # Sign the certificate
        if certificate.certificate_type == CertificateType.SERVER:
            cert_pem = ca_service.sign_csr(
                csr_pem=certificate.csr,
                validity_days=certificate.validity_days,
                cert_type=certificate.certificate_type,
            )
        else:
            logger.error(f"Failed to sign CSR for certificate {certificate.id}")
            raise ValueError("Only server certificates require approval")
        
        # Extract serial number and validity
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        serial_number = str(cert_obj.serial_number)
        not_before = cert_obj.not_valid_before_utc
        not_after = cert_obj.not_valid_after_utc
        
        # Update certificate record
        certificate.status = CertificateStatus.APPROVED
        certificate.certificate = cert_pem
        certificate.serial_number = serial_number
        certificate.not_before = not_before
        certificate.not_after = not_after
        certificate.approved_by_id = admin.id
        certificate.approved_at = datetime.utcnow()
        
        db.commit()
        db.refresh(certificate)
        
        # Audit log
        audit_service.log_certificate_approval(
            db=db,
            certificate_id=certificate.id,
            admin=admin,
            approved=True,
        )
        
        return certificate
    
    @staticmethod
    def reject_certificate(
        db: Session,
        certificate_id: int,
        admin: User,
        reason: str,
    ) -> Certificate:
        """Reject a pending certificate"""
        certificate = db.query(Certificate).filter(Certificate.id == certificate_id).first()
        
        if not certificate:
            logger.error(f"Certificate not found: {certificate_id}")
            raise ValueError("Certificate not found")
        
        if certificate.status != CertificateStatus.PENDING:
            logger.error(f"Certificate is not pending: {certificate.id}")
            raise ValueError("Certificate is not pending")
        
        # Update certificate record
        certificate.status = CertificateStatus.REJECTED
        certificate.revocation_reason = reason
        certificate.approved_by_id = admin.id
        certificate.approved_at = datetime.utcnow()
        
        db.commit()
        db.refresh(certificate)
        
        # Audit log
        audit_service.log_certificate_approval(
            db=db,
            certificate_id=certificate.id,
            admin=admin,
            approved=False,
            comment=reason if reason else None,
        )
        
        return certificate
    
    @staticmethod
    def revoke_certificate(
        db: Session,
        certificate_id: int,
        admin: User,
        reason: str,
    ) -> Certificate:
        """Revoke an approved certificate"""
        certificate = db.query(Certificate).filter(Certificate.id == certificate_id).first()
        
        if not certificate:
            logger.error(f"Certificate not found: {certificate_id}")
            raise ValueError("Certificate not found")
        
        if certificate.status != CertificateStatus.APPROVED:
            logger.error(f"Only approved certificates can be revoked: {certificate.id}")
            raise ValueError("Only approved certificates can be revoked")
        
        # Update certificate record
        certificate.status = CertificateStatus.REVOKED
        certificate.revoked_at = datetime.utcnow()
        certificate.revocation_reason = reason
        certificate.revoked_by_id = admin.id
        
        db.commit()
        db.refresh(certificate)
        
        # Update CRL
        CertificateService.update_crl(db)
        
        # Audit log
        audit_service.log_certificate_revocation(
            db=db,
            certificate_id=certificate.id,
            admin=admin,
            reason=reason,
        )
        
        return certificate
    
    @staticmethod
    def update_crl(db: Session) -> str:
        """Update the Certificate Revocation List"""
        # Get all revoked certificates
        revoked_certs = db.query(Certificate).filter(
            Certificate.status == CertificateStatus.REVOKED
        ).all()
        
        # Build list of (serial_number, revocation_date)
        revoked_list = [
            (int(cert.serial_number), cert.revoked_at)
            for cert in revoked_certs
            if cert.serial_number.isdigit()  # Skip pending certificates
        ]
        
        # Generate CRL
        crl_pem = ca_service.generate_crl(revoked_list)
        
        return crl_pem
    
    @staticmethod
    def get_certificates(
        db: Session,
        user: Optional[User] = None,
        status: Optional[CertificateStatus] = None,
        certificate_type: Optional[CertificateType] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> Tuple[List[Certificate], int]:
        """Get certificates with filtering and user details"""        
        query = db.query(Certificate).options(
            joinedload(Certificate.requested_by),
            joinedload(Certificate.approved_by),
            joinedload(Certificate.revoked_by),
        )
        
        # Filter by user if not admin
        if user and user.role.value != "admin":
            query = query.filter(Certificate.requested_by_id == user.id)
        
        # Apply filters
        if status:
            query = query.filter(Certificate.status == status)
        
        if certificate_type:
            query = query.filter(Certificate.certificate_type == certificate_type)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        certificates = query.order_by(Certificate.created_at.desc()).offset(skip).limit(limit).all()
        
        return certificates, total

    @staticmethod
    def get_certificate(db: Session, certificate_id: int) -> Optional[Certificate]:
        """Get a single certificate by ID"""
        return db.query(Certificate).options(
            joinedload(Certificate.requested_by),
            joinedload(Certificate.approved_by),
            joinedload(Certificate.revoked_by),
        ).filter(Certificate.id == certificate_id).first()
    
    def create_certificate_from_scep(
        db: Session,
        certificate_type: CertificateType,
        common_name: str,
        csr: str,
        certificate: str,
        scep_client_id: str,
        validation_message: str
    ) -> Certificate:
        """
        Create a certificate record from SCEP enrollment
        
        Args:
            certificate_type: Type of certificate (MACHINE or USER)
            common_name: Common name from CSR
            csr: CSR in PEM format
            certificate: Signed certificate in PEM format
            scep_client_id: UUID of SCEP client that requested it
            validation_message: Validation result message
            
        Returns:
            Certificate record
        """
        # Parse certificate to extract details
        cert_obj = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
        
        # Extract serial number
        serial_number = str(cert_obj.serial_number)
        
        # Extract validity dates
        not_before = cert_obj.not_valid_before
        not_after = cert_obj.not_valid_after
        
        # Calculate validity days
        validity_days = (not_after - not_before).days
        
        # Create certificate record
        cert_record = Certificate(
            certificate_type=certificate_type,
            common_name=common_name,
            serial_number=serial_number,
            csr=csr,
            certificate=certificate,
            status=CertificateStatus.APPROVED,  # Auto-approved for SCEP
            auto_approved=True,
            not_before=not_before,
            not_after=not_after,
            validity_days=validity_days,
            requested_by_id=None,  # No user for SCEP enrollment
            approved_by_id=None,   # Auto-approved
            subject_alternative_names=None  # Extract if needed
        )
        
        db.add(cert_record)
        db.commit()
        db.refresh(cert_record)
        
        audit_service.log_certificate_request(
            db=db,
            certificate_id=cert_record.id,
            certificate_type=certificate_type.value,
            user=None,  # No user for SCEP
            details={
                "scep_client_id": scep_client_id,
                "validation_message": validation_message
            }
        )
        return cert_record



certificate_service = CertificateService()