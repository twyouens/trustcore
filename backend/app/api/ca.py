from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.ca import CAInfoResponse, CRLResponse
from app.services.ca_service import ca_service
from app.services.certificate_service import certificate_service
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

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