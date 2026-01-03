"""
OCSP (Online Certificate Status Protocol) Service
Implements RFC 6960 for real-time certificate status checking
"""
from datetime import datetime, timedelta
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.orm import Session

from app.models.certificate import Certificate, CertificateStatus
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class OCSPService:
    """Service for handling OCSP requests and responses"""
    
    def __init__(self, ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate):
        """
        Initialize OCSP service
        
        Args:
            ca_key: CA private key for signing OCSP responses
            ca_cert: CA certificate
        """
        self.ca_key = ca_key
        self.ca_cert = ca_cert
    
    def process_request(
        self, 
        ocsp_request_data: bytes, 
        db: Session
    ) -> Tuple[bytes, str]:
        """
        Process an OCSP request and return a signed response
        
        Args:
            ocsp_request_data: Raw OCSP request bytes
            db: Database session
            
        Returns:
            Tuple of (response_bytes, content_type)
        """
        try:
            # Parse OCSP request
            ocsp_request = ocsp.load_der_ocsp_request(ocsp_request_data)
            
            # Get the certificate serial number from the request
            serial_number = ocsp_request.serial_number
            
            logger.info(f"OCSP request for certificate serial: {serial_number}")
            
            # Query database for certificate status
            cert_record = db.query(Certificate).filter(
                Certificate.serial_number == str(serial_number)
            ).first()
            
            # Determine certificate status
            if cert_record is None:
                # Certificate not found
                cert_status = ocsp.OCSPCertStatus.UNKNOWN
                revocation_time = None
                revocation_reason = None
                logger.warning(f"OCSP request for unknown certificate: {serial_number}")
            elif cert_record.status == CertificateStatus.REVOKED:
                # Certificate is revoked
                cert_status = ocsp.OCSPCertStatus.REVOKED
                revocation_time = cert_record.revoked_at
                # Map revocation reason to OCSP reason
                revocation_reason = self._map_revocation_reason(cert_record.revocation_reason)
                logger.info(f"OCSP response: Certificate {serial_number} is REVOKED")
            else:
                # Certificate is good (approved and not revoked)
                cert_status = ocsp.OCSPCertStatus.GOOD
                revocation_time = None
                revocation_reason = None
                logger.info(f"OCSP response: Certificate {serial_number} is GOOD")
            
            # Build OCSP response
            response = self._build_response(
                ocsp_request=ocsp_request,
                cert_status=cert_status,
                revocation_time=revocation_time,
                revocation_reason=revocation_reason,
                cert_record=cert_record
            )
            
            # Serialize response
            response_bytes = response.public_bytes(serialization.Encoding.DER)
            
            return response_bytes, "application/ocsp-response"
            
        except Exception as e:
            logger.error(f"Error processing OCSP request: {str(e)}")
            # Return an error response
            return self._build_error_response(), "application/ocsp-response"
    
    def _build_response(
        self,
        ocsp_request: ocsp.OCSPRequest,
        cert_status: ocsp.OCSPCertStatus,
        revocation_time: Optional[datetime],
        revocation_reason: Optional[x509.ReasonFlags],
        cert_record: Optional[Certificate]
    ) -> ocsp.OCSPResponse:
        """
        Build an OCSP response
        
        Args:
            ocsp_request: The OCSP request
            cert_status: Certificate status (GOOD, REVOKED, UNKNOWN)
            revocation_time: When certificate was revoked (if applicable)
            revocation_reason: Reason for revocation (if applicable)
            cert_record: Database certificate record (if found)
            
        Returns:
            OCSP response object
        """
        # Current time
        this_update = datetime.utcnow()
        # Next update (OCSP response validity period)
        next_update = this_update + timedelta(hours=settings.CRL_UPDATE_HOURS)
        
        # Build the response based on status
        builder = ocsp.OCSPResponseBuilder()
        
        if cert_status == ocsp.OCSPCertStatus.GOOD:
            builder = builder.add_response(
                cert=self._get_certificate_from_record(cert_record),
                issuer=self.ca_cert,
                algorithm=hashes.SHA256(),
                cert_status=cert_status,
                this_update=this_update,
                next_update=next_update,
                revocation_time=None,
                revocation_reason=None
            )
        elif cert_status == ocsp.OCSPCertStatus.REVOKED:
            builder = builder.add_response(
                cert=self._get_certificate_from_record(cert_record),
                issuer=self.ca_cert,
                algorithm=hashes.SHA256(),
                cert_status=cert_status,
                this_update=this_update,
                next_update=next_update,
                revocation_time=revocation_time,
                revocation_reason=revocation_reason
            )
        else:  # UNKNOWN
            # For unknown certificates, we need to use the serial from the request
            builder = builder.add_response(
                cert=None,  # Certificate not found
                issuer=self.ca_cert,
                algorithm=hashes.SHA256(),
                cert_status=cert_status,
                this_update=this_update,
                next_update=next_update,
                revocation_time=None,
                revocation_reason=None
            ).serial_number(ocsp_request.serial_number)
        
        # Sign the response with CA key
        response = builder.sign(self.ca_key, hashes.SHA256())
        
        return response
    
    def _get_certificate_from_record(self, cert_record: Certificate) -> x509.Certificate:
        """
        Load certificate from database record
        
        Args:
            cert_record: Database certificate record
            
        Returns:
            X.509 certificate object
        """
        cert_pem = cert_record.certificate.encode()
        cert = x509.load_pem_x509_certificate(cert_pem)
        return cert
    
    def _map_revocation_reason(self, reason_str: Optional[str]) -> Optional[x509.ReasonFlags]:
        """
        Map revocation reason string to OCSP reason flag
        
        Args:
            reason_str: Revocation reason string from database
            
        Returns:
            X.509 ReasonFlags enum value
        """
        if not reason_str:
            return None
        
        reason_map = {
            "unspecified": x509.ReasonFlags.unspecified,
            "key_compromise": x509.ReasonFlags.key_compromise,
            "ca_compromise": x509.ReasonFlags.ca_compromise,
            "affiliation_changed": x509.ReasonFlags.affiliation_changed,
            "superseded": x509.ReasonFlags.superseded,
            "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
            "certificate_hold": x509.ReasonFlags.certificate_hold,
            "remove_from_crl": x509.ReasonFlags.remove_from_crl,
            "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
            "aa_compromise": x509.ReasonFlags.aa_compromise,
        }
        
        return reason_map.get(reason_str.lower(), x509.ReasonFlags.unspecified)
    
    def _build_error_response(self) -> bytes:
        """
        Build an OCSP error response
        
        Returns:
            Serialized OCSP error response
        """
        # Build a simple error response
        builder = ocsp.OCSPResponseBuilder()
        response = builder.build_unsuccessful(ocsp.OCSPResponseStatus.INTERNAL_ERROR)
        return response.public_bytes(serialization.Encoding.DER)