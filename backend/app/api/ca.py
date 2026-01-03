from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.ca import CAInfoResponse, CRLResponse
from app.services.ca_service import CAService, ca_service
from app.services.certificate_service import certificate_service
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app.services.ocsp_service import OCSPService
from app.core.logging import get_logger
from app.services.audit_service import audit_service
from app.core.config import settings

logger = get_logger(__name__)

router = APIRouter(prefix="/ca", tags=["certificate-authority"])


@router.get("/certificate", response_class=PlainTextResponse)
async def get_ca_certificate():
    """
    Get CA certificate in PEM format
    This is public and doesn't require authentication
    """
    ca_cert_pem = ca_service.get_ca_certificate()
    return PlainTextResponse(
        content=ca_cert_pem,
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition": 'attachment; filename="ca-certificate.pem"'
        },
    )


@router.get("/info", response_model=CAInfoResponse)
async def get_ca_info():
    """
    Get CA certificate information
    Public endpoint
    """
    ca_cert_pem = ca_service.get_ca_certificate()
    
    # Parse certificate to extract info
    cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
    
    return CAInfoResponse(
        ca_certificate=ca_cert_pem,
        ca_name=cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        serial_number=str(cert.serial_number),
        issuer=cert.issuer.rfc4514_string(),
        subject=cert.subject.rfc4514_string(),
    )


@router.get("/crl", response_class=PlainTextResponse)
async def get_crl(db: Session = Depends(get_db)):
    """
    Get Certificate Revocation List (CRL) in PEM format
    Public endpoint for CRL distribution
    """
    # Update CRL with latest revoked certificates
    crl_pem = certificate_service.update_crl(db)
    
    return PlainTextResponse(
        content=crl_pem,
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition": 'attachment; filename="crl.pem"'
        },
    )


@router.get("/crl/info", response_model=CRLResponse)
async def get_crl_info(db: Session = Depends(get_db)):
    """
    Get CRL information
    Public endpoint
    """
    # Update and get CRL
    crl_pem = certificate_service.update_crl(db)
    
    # Parse CRL to extract info
    crl = x509.load_pem_x509_crl(crl_pem.encode(), default_backend())
    
    return CRLResponse(
        crl=crl_pem,
        last_update=crl.last_update_utc,
        next_update=crl.next_update_utc,
    )


@router.post("/ocsp",
    summary="OCSP Responder",
    description="Online Certificate Status Protocol endpoint for real-time certificate validation (RFC 6960)",
    response_class=Response,
    responses={
        200: {
            "description": "OCSP response in DER format",
            "content": {"application/ocsp-response": {"schema": {"type": "string", "format": "binary"}}}
        }
    })
async def ocsp_responder(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    OCSP Responder endpoint (RFC 6960)
    
    Accepts OCSP requests in DER format and returns certificate status:
    - **GOOD**: Certificate is valid and not revoked
    - **REVOKED**: Certificate has been revoked (includes revocation time and reason)
    - **UNKNOWN**: Certificate not found in database
    
    **This endpoint does not require authentication.**
    
    The request and response are binary data (DER-encoded ASN.1).
    OCSP clients (like OpenSSL, browsers, etc.) send requests automatically.
    
    Example usage with OpenSSL:
    ```bash
    openssl ocsp -issuer ca.pem -cert cert.pem \\
                 -url http://localhost:8000/api/v1/ca/ocsp
    ```
    """
    try:
        # Read raw request body (DER-encoded OCSP request)
        ocsp_request_data = await request.body()
        
        if not ocsp_request_data:
            logger.error("Empty OCSP request received")
            return Response(
                content=b"",
                status_code=400,
                media_type="application/ocsp-response"
            )
        
        # Initialize CA service and get CA key/cert
        ca_service = CAService()
        ca_key = ca_service._load_ca_key()
        ca_cert = ca_service._load_ca_certificate()

        # Initialize OCSP service
        ocsp_service = OCSPService(ca_key=ca_key, ca_cert=ca_cert)
        
        # Process OCSP request
        response_bytes, content_type = ocsp_service.process_request(
            ocsp_request_data=ocsp_request_data,
            db=db
        )
        
        # Log OCSP request (without user since it's public endpoint)
        audit_service.log_ocsp_request(
            db=db,
            user=None,
            ip_address=request.client.host if request.client else None,
            request_size=len(ocsp_request_data),
            response_size=len(response_bytes)
        )

        return Response(
            content=response_bytes,
            status_code=200,
            media_type=content_type,
            headers={
                "Cache-Control": f"max-age={settings.CRL_UPDATE_HOURS * 3600}",
            }
        )
        
    except Exception as e:
        logger.error(f"OCSP responder error: {str(e)}")
        return Response(
            content=b"",
            status_code=500,
            media_type="application/ocsp-response"
        )


@router.get("/ocsp/{encoded_request}",
    summary="OCSP Responder (GET)",
    description="OCSP GET method support with base64-encoded request in URL path",
    response_class=Response,
    responses={
        200: {
            "description": "OCSP response in DER format",
            "content": {"application/ocsp-response": {"schema": {"type": "string", "format": "binary"}}}
        }
    })
async def ocsp_responder_get(
    encoded_request: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    OCSP Responder GET method
    
    Some OCSP clients prefer GET method with base64-encoded request in URL.
    Format: `/api/v1/ca/ocsp/{base64_url_encoded_request}`
    
    **This endpoint does not require authentication.**
    
    The request is URL-safe base64 encoded in the path, and the response
    is binary DER-encoded data.
    """
    import base64
    
    try:
        # URL-safe base64 decode
        # Add padding if needed
        padding = 4 - (len(encoded_request) % 4)
        if padding != 4:
            encoded_request += '=' * padding
        
        ocsp_request_data = base64.urlsafe_b64decode(encoded_request)
        
        # Initialize CA service and get CA key/cert
        ca_service = CAService()
        ca_key = ca_service._load_ca_key()
        ca_cert = ca_service._load_ca_certificate()
        
        # Initialize OCSP service
        ocsp_service = OCSPService(ca_key=ca_key, ca_cert=ca_cert)
        
        # Process OCSP request
        response_bytes, content_type = ocsp_service.process_request(
            ocsp_request_data=ocsp_request_data,
            db=db
        )
        
        # Log OCSP request
        audit_service.log_ocsp_request(
            db=db,
            user=None,
            ip_address=request.client.host if request.client else None,
            request_size=len(ocsp_request_data),
            response_size=len(response_bytes)
        )
        
        return Response(
            content=response_bytes,
            status_code=200,
            media_type=content_type,
            headers={
                "Cache-Control": f"max-age={settings.CRL_UPDATE_HOURS * 3600}",
            }
        )
            
    except Exception as e:
        logger.error(f"OCSP responder GET error: {str(e)}")
        return Response(
            content=b"",
            status_code=500,
            media_type="application/ocsp-response"
        )