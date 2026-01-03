from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, Field, HttpUrl, field_validator

from app.schemas.user import UserSnippet


class SCEPClientCreate(BaseModel):
    """Schema for creating a new SCEP client"""
    name: str = Field(..., min_length=1, max_length=255, description="Client name (e.g., 'Intune Production')")
    description: Optional[str] = Field(None, description="Optional description")
    allowed_certificate_types: List[str] = Field(
        ...,
        description="Certificate types this client can request",
        min_length=1
    )
    user_validation_url: Optional[str] = Field(
        None,
        max_length=500,
        description="URL to validate user certificates (optional)"
    )
    machine_validation_url: Optional[str] = Field(
        None,
        max_length=500,
        description="URL to validate machine certificates (optional)"
    )
    enabled: bool = Field(True, description="Whether client is enabled")
    
    @field_validator('allowed_certificate_types')
    @classmethod
    def validate_cert_types(cls, v):
        """Validate certificate types"""
        allowed_types = {'MACHINE', 'USER'}
        for cert_type in v:
            if cert_type not in allowed_types:
                raise ValueError(f"Invalid certificate type: {cert_type}. Must be one of: {allowed_types}")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "Intune Production",
                "description": "Microsoft Intune for corporate devices",
                "allowed_certificate_types": ["MACHINE", "USER"],
                "user_validation_url": "https://identity.corp.com/api/validate-user",
                "machine_validation_url": "https://cmdb.corp.com/api/validate-mac",
                "enabled": True
            }
        }


class SCEPClientResponse(BaseModel):
    """Schema for SCEP client response"""
    id: UUID
    name: str
    description: Optional[str]
    allowed_certificate_types: List[str]
    user_validation_url: Optional[str]
    machine_validation_url: Optional[str]
    enabled: bool
    scep_url: str = Field(..., description="SCEP endpoint URL for this client")
    total_requests: int
    successful_requests: int
    failed_requests: int
    last_used_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    created_by: UserSnippet
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Intune Production",
                "description": "Microsoft Intune for corporate devices",
                "allowed_certificate_types": ["MACHINE", "USER"],
                "user_validation_url": "https://identity.corp.com/api/validate-user",
                "machine_validation_url": "https://cmdb.corp.com/api/validate-mac",
                "enabled": True,
                "scep_url": "https://trustcore.corp.com/api/v1/scep/550e8400-e29b-41d4-a716-446655440000/pkiclient.exe",
                "total_requests": 1523,
                "successful_requests": 1498,
                "failed_requests": 25,
                "last_used_at": "2026-01-03T08:30:00Z",
                "created_at": "2025-12-01T10:00:00Z",
                "updated_at": "2026-01-03T08:30:00Z",
                "created_by": {
                    "id": 1,
                    "username": "admin",
                    "email": "admin@example.com",
                    "full_name": "Admin User"
                }
            }
        }


class SCEPClientUpdate(BaseModel):
    """Schema for updating a SCEP client"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    allowed_certificate_types: Optional[List[str]] = None
    user_validation_url: Optional[str] = Field(None, max_length=500)
    machine_validation_url: Optional[str] = Field(None, max_length=500)
    enabled: Optional[bool] = None
    
    @field_validator('allowed_certificate_types')
    @classmethod
    def validate_cert_types(cls, v):
        """Validate certificate types"""
        if v is None:
            return v
        allowed_types = {'MACHINE', 'USER'}
        for cert_type in v:
            if cert_type not in allowed_types:
                raise ValueError(f"Invalid certificate type: {cert_type}. Must be one of: {allowed_types}")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "Intune Production (Updated)",
                "description": "Updated description",
                "enabled": False
            }
        }


class SCEPClientStats(BaseModel):
    """Schema for SCEP client statistics"""
    id: UUID
    name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    success_rate: float = Field(..., description="Success rate as percentage")
    last_used_at: Optional[datetime]
    
    class Config:
        from_attributes = True