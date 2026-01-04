from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List, Any
from datetime import datetime
from app.models.certificate import CertificateType, CertificateStatus
from app.schemas.user import UserSnippet
from enum import Enum
import re
import json


class CertificateFormat(str, Enum):
    PEM = "pem"
    PKCS12 = "pkcs12"
    DER = "der"


class CertificateRequestBase(BaseModel):
    certificate_type: CertificateType
    validity_days: int = Field(default=365, ge=1, le=3650)
    output_format: CertificateFormat = Field(default=CertificateFormat.PEM)
    pkcs12_password: Optional[str] = Field(default=None, description="Password for PKCS12 format. If not provided, defaults to username.")


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


class CertificateDownloadRequest(BaseModel):
    output_format: CertificateFormat = Field(default=CertificateFormat.PEM)
    pkcs12_password: Optional[str] = Field(default=None, description="Password for PKCS12 format. If not provided, defaults to username.")


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
    requested_by_id: Optional[int] = None
    approved_by_id: Optional[int] = None
    revoked_by_id: Optional[int] = None
    auto_approved: bool
    
    # User snippets
    requested_by: Optional[UserSnippet] = None
    approved_by: Optional[UserSnippet] = None
    revoked_by: Optional[UserSnippet] = None
    
    @model_validator(mode='before')
    @classmethod
    def parse_sans(cls, data: Any) -> Any:
        """Parse subject_alternative_names from JSON string if needed"""
        # Handle SQLAlchemy model objects
        if hasattr(data, 'subject_alternative_names'):
            sans = data.subject_alternative_names
            if sans and isinstance(sans, str):
                try:
                    # Parse and set it back on the object
                    parsed_sans = json.loads(sans)
                    # Create a dict from the model for modification
                    if hasattr(data, '__dict__'):
                        data_dict = {k: v for k, v in data.__dict__.items() if not k.startswith('_')}
                        data_dict['subject_alternative_names'] = parsed_sans
                        return data_dict
                except (json.JSONDecodeError, TypeError):
                    pass
        
        # Handle dict input
        if isinstance(data, dict):
            sans = data.get('subject_alternative_names')
            if sans and isinstance(sans, str):
                try:
                    data['subject_alternative_names'] = json.loads(sans)
                except (json.JSONDecodeError, TypeError):
                    data['subject_alternative_names'] = None
        
        return data
    
    class Config:
        from_attributes = True


class CertificateDetailResponse(CertificateResponse):
    certificate: Optional[str] = None  # PEM encoded certificate
    csr: Optional[str] = None  # PEM encoded CSR


class CertificateListResponse(BaseModel):
    total: int
    items: List[CertificateResponse]