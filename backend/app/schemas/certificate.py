from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import datetime
from app.models.certificate import CertificateType, CertificateStatus
import re


class CertificateRequestBase(BaseModel):
    certificate_type: CertificateType
    validity_days: int = Field(default=365, ge=1, le=3650)


class MachineCertificateRequest(CertificateRequestBase):
    certificate_type: CertificateType = CertificateType.MACHINE
    mac_address: str
    
    @field_validator('mac_address')
    @classmethod
    def validate_mac_address(cls, v: str) -> str:
        # Validate MAC address format AA:BB:CC:DD:EE:FF
        pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
        if not re.match(pattern, v):
            raise ValueError('MAC address must be in format AA:BB:CC:DD:EE:FF')
        return v.upper()


class UserCertificateRequest(CertificateRequestBase):
    certificate_type: CertificateType = CertificateType.USER
    username: Optional[str] = None  # If None, use authenticated user's username


class ServerCertificateRequest(CertificateRequestBase):
    certificate_type: CertificateType = CertificateType.SERVER
    csr: str  # PEM encoded CSR
    
    @field_validator('csr')
    @classmethod
    def validate_csr(cls, v: str) -> str:
        if not v.startswith('-----BEGIN CERTIFICATE REQUEST-----'):
            raise ValueError('CSR must be in PEM format')
        return v


class CertificateApproval(BaseModel):
    approved: bool
    rejection_reason: Optional[str] = None


class CertificateRevocation(BaseModel):
    reason: str


class CertificateResponse(BaseModel):
    id: int
    serial_number: str
    certificate_type: CertificateType
    common_name: str
    subject_alternative_names: Optional[List[str]] = None
    status: CertificateStatus
    validity_days: int
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    created_at: datetime
    approved_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    requested_by_id: int
    approved_by_id: Optional[int] = None
    revoked_by_id: Optional[int] = None
    auto_approved: bool
    
    class Config:
        from_attributes = True


class CertificateDetailResponse(CertificateResponse):
    certificate: Optional[str] = None  # PEM encoded certificate
    csr: Optional[str] = None  # PEM encoded CSR


class CertificateListResponse(BaseModel):
    total: int
    items: List[CertificateResponse]