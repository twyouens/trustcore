"""
SCEP Protocol Endpoints - app/api/scep.py (Using CertificateFormatter)
Simplified implementation leveraging existing certificate_formatter service
"""
from uuid import UUID
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session
import logging

from app.core.database import get_db
from app.services.ca_service import CAService
from app.services.scep_service import SCEPService
from app.services.scep_client_service import SCEPClientService
from app.services.audit_service import audit_service
from app.services.certificate_service import certificate_service
from app.services.certificate_formatter import certificate_formatter
from app.models.certificate import CertificateType
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scep", tags=["SCEP Protocol"])


@router.get("/{client_id}/pkiclient.exe",
    summary="SCEP GetCACert/GetCACaps",
    description="SCEP protocol endpoint for GetCACert and GetCACaps operations",
    response_class=Response)
async def scep_get(
    client_id: UUID,
    operation: str,
    db: Session = Depends(get_db)
):
    """
    SCEP GET operations: GetCACert and GetCACaps
    
    This endpoint handles:
    - GetCACert: Returns CA certificate in PKCS#7 format
    - GetCACaps: Returns CA capabilities
    
    **No authentication required** (SCEP protocol design)
    """
    # Validate SCEP client
    scep_client = SCEPClientService.validate_client(db, client_id)
    if not scep_client:
        logger.warning(f"Invalid SCEP client ID: {client_id}")
        return Response(
            content=b"Invalid SCEP client",
            status_code=403,
            media_type="text/plain"
        )
    
    ca_service = CAService()
    
    try:
        if operation == "GetCACert":
            # Get CA certificate
            ca_cert_pem = ca_service.get_ca_certificate()
            
            # Convert to PKCS#7 (degenerate - certificates only)
            pkcs7_data = certificate_formatter.to_pkcs7(
                certificate_pem=ca_cert_pem,
                ca_cert_pem=ca_cert_pem,  # Include CA cert in chain
                include_chain=True
            )
            
            # Update client stats
            SCEPClientService.increment_stats(db, client_id, success=True)

            logger.info(f"SCEP GetCACert successful for client: {client_id}")
            return Response(
                content=pkcs7_data,
                status_code=200,
                media_type=certificate_formatter.get_media_type('pkcs7')
            )
        
        elif operation == "GetCACaps":
            # Return CA capabilities
            ca_caps = SCEPService.get_ca_caps()
            
            # Update client stats
            SCEPClientService.increment_stats(db, client_id, success=True)
            
            # Log
            logger.info(f"SCEP GetCACaps successful for client: {client_id}")

            return Response(
                content=ca_caps.encode(),
                status_code=200,
                media_type="text/plain"
            )
        
        else:
            logger.warning(f"Unknown SCEP operation: {operation}")
            SCEPClientService.increment_stats(db, client_id, success=False)
            return Response(
                content=b"Unknown operation",
                status_code=400,
                media_type="text/plain"
            )
    
    except Exception as e:
        logger.error(f"SCEP GET error: {str(e)}")
        SCEPClientService.increment_stats(db, client_id, success=False)
        return Response(
            content=b"Internal server error",
            status_code=500,
            media_type="text/plain"
        )


@router.post("/{client_id}/pkiclient.exe",
    summary="SCEP PKIOperation",
    description="SCEP protocol endpoint for certificate enrollment (PKIOperation)",
    response_class=Response)
async def scep_post(
    client_id: UUID,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    SCEP POST operation: PKIOperation (certificate enrollment)
    
    This endpoint handles certificate signing requests from MDM systems.
    Accepts PKCS#7 wrapped CSRs or plain PEM/DER CSRs.
    Returns signed certificate wrapped in PKCS#7.
    
    **No authentication required** (SCEP protocol design)
    """
    # Validate SCEP client
    scep_client = SCEPClientService.validate_client(db, client_id)
    if not scep_client:
        logger.warning(f"Invalid SCEP client ID: {client_id}")
        SCEPClientService.increment_stats(db, client_id, success=False)
        return Response(
            content=b"Invalid SCEP client",
            status_code=403,
            media_type="text/plain"
        )
    
    try:
        # Read request body
        body = await request.body()
        
        # Unwrap PKCS#7 to get CSR (also accepts plain PEM/DER)
        csr_pem, error_msg = certificate_formatter.unwrap_pkcs7_csr(body)
        
        if not csr_pem:
            logger.error(f"Failed to parse CSR: {error_msg}")
            SCEPClientService.increment_stats(db, client_id, success=False)
            
            # Audit log
            audit_service.log_scep_enrollment_rejected(
                client_id=client_id,
                client_name=scep_client.name,
                error=error_msg
            )

            return Response(
                content=error_msg.encode(),
                status_code=400,
                media_type="text/plain"
            )
        
        # Parse CSR
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        except Exception as e:
            logger.error(f"Failed to load CSR: {str(e)}")
            SCEPClientService.increment_stats(db, client_id, success=False)
            return Response(
                content=b"Invalid CSR format",
                status_code=400,
                media_type="text/plain"
            )
        
        # Detect certificate type
        cert_type = SCEPService.detect_certificate_type(csr)
        if not cert_type:
            logger.error("Could not detect certificate type")
            SCEPClientService.increment_stats(db, client_id, success=False)
            return Response(
                content=b"Could not detect certificate type",
                status_code=400,
                media_type="text/plain"
            )
        
        # Validate certificate request
        is_valid, validation_message = await SCEPService.validate_certificate_request(
            csr, cert_type, scep_client
        )
        
        if not is_valid:
            logger.warning(f"Certificate validation failed: {validation_message}")
            SCEPClientService.increment_stats(db, client_id, success=False)
            
            # Audit log
            audit_service.log_scep_enrollment_failed(
                db=db,
                user=scep_client.user,
                client_id=client_id,
                ip_address=request.client.host,
                reason=validation_message
            )
            
            return Response(
                content=validation_message.encode(),
                status_code=403,
                media_type="text/plain"
            )
        
        # Sign the certificate
        ca_service = CAService()
        cert_pem = ca_service.sign_csr(
            csr_pem=csr_pem,
            cert_type=cert_type
        )
        
        # Store certificate in database
        common_name = SCEPService.get_common_name(csr)
        if not common_name:
            common_name = "SCEP-enrolled"
        
        # Normalize MAC address if it's a machine cert
        if cert_type == CertificateType.MACHINE:
            common_name = SCEPService.normalize_mac_address(common_name)
        
        # Create certificate record
        cert_record = certificate_service.create_certificate_from_scep(
            certificate_type=cert_type,
            common_name=common_name,
            csr=csr_pem,
            certificate=cert_pem,
            scep_client_id=str(client_id),
            validation_message=validation_message
        )
        
        # Update client stats
        SCEPClientService.increment_stats(db, client_id, success=True)
        
        # Audit log
        audit_service.log_scep_enrollment_success(
            db=db,
            user=scep_client.user,
            client_id=client_id,
            ip_address=request.client.host,
            cert_type=cert_type.value,
            common_name=common_name,
            serial_number=cert_record.serial_number,
            validation_message=validation_message
        )
        
        logger.info(
            f"SCEP enrollment successful: {cert_type.value} certificate for {common_name} "
            f"via client {scep_client.name}"
        )
        
        # Get CA certificate for PKCS#7 chain
        ca_cert_pem = ca_service.get_ca_certificate()
        
        # Wrap certificate in PKCS#7 with CA cert chain
        pkcs7_response = certificate_formatter.to_pkcs7(
            certificate_pem=cert_pem,
            ca_cert_pem=ca_cert_pem,
            include_chain=True
        )
        
        return Response(
            content=pkcs7_response,
            status_code=200,
            media_type=certificate_formatter.get_media_type('pkcs7')
        )
    
    except Exception as e:
        logger.error(f"SCEP enrollment error: {str(e)}", exc_info=True)
        SCEPClientService.increment_stats(db, client_id, success=False)
        
        # Audit log
        logger.error(f"SCEP enrollment error: {str(e)}", exc_info=True)
        
        return Response(
            content=b"Internal server error",
            status_code=500,
            media_type="text/plain"
        )