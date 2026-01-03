from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Literal


class CAInfoResponse(BaseModel):
    """CA certificate information"""
    ca_certificate: str  # PEM encoded CA certificate
    ca_name: str
    not_before: datetime
    not_after: datetime
    serial_number: str
    issuer: str
    subject: str


class CRLResponse(BaseModel):
    """Certificate Revocation List response"""
    crl: str  # PEM encoded CRL
    last_update: datetime
    next_update: datetime


class OCSPRequest(BaseModel):
    """
    OCSP request - This is actually handled as raw bytes in the endpoint
    but we define this schema for documentation purposes
    """
    # Note: OCSP requests come as DER-encoded binary data
    # This schema is for API documentation only
    # The actual endpoint accepts raw bytes in the request body
    
    class Config:
        json_schema_extra = {
            "description": "OCSP request in DER format (application/ocsp-request)",
            "example": "Binary OCSP request data"
        }


class OCSPResponse(BaseModel):
    """
    OCSP response - This is actually returned as raw bytes
    but we define this schema for documentation purposes
    """
    # Note: OCSP responses are returned as DER-encoded binary data
    # This schema is for API documentation only
    # The actual endpoint returns raw bytes (application/ocsp-response)
    
    class Config:
        json_schema_extra = {
            "description": "OCSP response in DER format (application/ocsp-response)",
            "example": "Binary OCSP response data"
        }


# Alternative: If you want structured responses for debugging/logging
class OCSPStatusResponse(BaseModel):
    """
    Structured OCSP status response (for API documentation/debugging)
    Not used in actual OCSP protocol - just for human-readable status
    """
    serial_number: str = Field(..., description="Certificate serial number")
    status: Literal["good", "revoked", "unknown"] = Field(..., description="Certificate status")
    this_update: datetime = Field(..., description="Response generation time")
    next_update: datetime = Field(..., description="Next response update time")
    revocation_time: Optional[datetime] = Field(None, description="When certificate was revoked (if revoked)")
    revocation_reason: Optional[str] = Field(None, description="Reason for revocation (if revoked)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "serial_number": "123456789",
                "status": "good",
                "this_update": "2026-01-03T10:00:00Z",
                "next_update": "2026-01-04T10:00:00Z",
                "revocation_time": None,
                "revocation_reason": None
            }
        }