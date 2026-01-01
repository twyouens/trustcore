from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from typing import Optional, List
from app.core.database import get_db
from app.schemas.certificate import (
    MachineCertificateRequest,
    UserCertificateRequest,
    ServerCertificateRequest,
    CertificateApproval,
    CertificateRevocation,
    CertificateResponse,
    CertificateDetailResponse,
    CertificateListResponse,
)
from app.models.certificate import CertificateType, CertificateStatus
from app.models.user import User, UserRole
from app.services.auth_service import get_current_user, get_current_admin
from app.services.certificate_service import certificate_service
from app.services.audit_service import audit_service
import json

router = APIRouter(prefix="/certificates", tags=["certificates"])


@router.post("/machine", response_model=CertificateDetailResponse)
async def request_machine_certificate(
    request: MachineCertificateRequest,
    current_user: User = Depends(get_current_admin),  # Only admins can generate machine certs
    db: Session = Depends(get_db),
):
    """
    Generate a machine certificate for EAP-TLS authentication
    Requires admin role
    Auto-approved and immediately generated
    """
    try:
        certificate, private_key = certificate_service.request_machine_certificate(
            db=db,
            mac_address=request.mac_address,
            validity_days=request.validity_days,
            user=current_user,
            auto_approve=True,
        )
        
        # Prepare response with certificate details
        response = CertificateDetailResponse.model_validate(certificate)
        
        # Include private key in response (only time it's available)
        # In production, consider more secure delivery method
        if private_key:
            response.certificate = f"{private_key}\n{certificate.certificate}"
        
        return response
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/user", response_model=CertificateDetailResponse)
async def request_user_certificate(
    request: UserCertificateRequest,
    current_user: User = Depends(get_current_admin),  # Only admins can generate user certs
    db: Session = Depends(get_db),
):
    """
    Generate a user certificate for EAP-TLS authentication
    Requires admin role
    Auto-approved and immediately generated
    """
    try:
        # Use specified username or current user's username
        username = request.username or current_user.username
        
        certificate, private_key = certificate_service.request_user_certificate(
            db=db,
            username=username,
            validity_days=request.validity_days,
            user=current_user,
            auto_approve=True,
        )
        
        # Prepare response with certificate details
        response = CertificateDetailResponse.model_validate(certificate)
        
        # Include private key in response
        if private_key:
            response.certificate = f"{private_key}\n{certificate.certificate}"
        
        return response
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/server", response_model=CertificateResponse)
async def request_server_certificate(
    request: ServerCertificateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Request a server certificate by uploading CSR
    Requires approval from admin
    """
    try:
        certificate = certificate_service.request_server_certificate(
            db=db,
            csr_pem=request.csr,
            validity_days=request.validity_days,
            user=current_user,
        )
        
        return certificate
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get("", response_model=CertificateListResponse)
async def list_certificates(
    status: Optional[CertificateStatus] = Query(None),
    certificate_type: Optional[CertificateType] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    List certificates
    Users see only their own certificates
    Admins see all certificates
    """
    # Pass user only if not admin (admins see all)
    filter_user = None if current_user.role == UserRole.ADMIN else current_user
    
    certificates, total = certificate_service.get_certificates(
        db=db,
        user=filter_user,
        status=status,
        certificate_type=certificate_type,
        skip=skip,
        limit=limit,
    )
    
    return CertificateListResponse(
        total=total,
        items=certificates,
    )


@router.get("/{certificate_id}", response_model=CertificateDetailResponse)
async def get_certificate(
    certificate_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get certificate details"""
    certificate = db.query(
        certificate_service.Certificate
    ).filter_by(id=certificate_id).first()
    
    if not certificate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found",
        )
    
    # Check permissions
    if current_user.role != UserRole.ADMIN and certificate.requested_by_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this certificate",
        )
    
    return certificate


@router.get("/{certificate_id}/download", response_class=PlainTextResponse)
async def download_certificate(
    certificate_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download certificate in PEM format"""
    from app.models.certificate import Certificate
    
    certificate = db.query(Certificate).filter_by(id=certificate_id).first()
    
    if not certificate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found",
        )
    
    # Check permissions
    if current_user.role != UserRole.ADMIN and certificate.requested_by_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to download this certificate",
        )
    
    if certificate.status != CertificateStatus.APPROVED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Certificate is not approved",
        )
    
    if not certificate.certificate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate data not available",
        )
    
    # Audit log
    audit_service.log_certificate_download(
        db=db,
        certificate_id=certificate.id,
        user=current_user,
    )
    
    return Response(
        content=certificate.certificate,
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition": f'attachment; filename="{certificate.common_name}.pem"'
        },
    )


@router.post("/{certificate_id}/approve", response_model=CertificateResponse)
async def approve_certificate(
    certificate_id: int,
    approval: CertificateApproval,
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """
    Approve or reject a pending certificate
    Requires admin role
    """
    try:
        if approval.approved:
            certificate = certificate_service.approve_certificate(
                db=db,
                certificate_id=certificate_id,
                admin=current_user,
            )
        else:
            if not approval.rejection_reason:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Rejection reason is required",
                )
            certificate = certificate_service.reject_certificate(
                db=db,
                certificate_id=certificate_id,
                admin=current_user,
                reason=approval.rejection_reason,
            )
        
        return certificate
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/{certificate_id}/revoke", response_model=CertificateResponse)
async def revoke_certificate(
    certificate_id: int,
    revocation: CertificateRevocation,
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """
    Revoke an approved certificate
    Requires admin role
    """
    try:
        certificate = certificate_service.revoke_certificate(
            db=db,
            certificate_id=certificate_id,
            admin=current_user,
            reason=revocation.reason,
        )
        
        return certificate
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )