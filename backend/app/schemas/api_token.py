from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator

from app.schemas.user import UserSnippet


class APITokenCreate(BaseModel):
    """Schema for creating a new API token"""
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable token name")
    description: Optional[str] = Field(None, description="Optional token description")
    scopes: Optional[List[str]] = Field(None, description="Optional list of permission scopes")
    expires_in_days: Optional[int] = Field(None, gt=0, le=3650, description="Token expiry in days (max 10 years)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "CI/CD Pipeline Token",
                "description": "Token for automated certificate generation in CI/CD",
                "scopes": ["certificates:read", "certificates:write"],
                "expires_in_days": 365
            }
        }


class APITokenCreated(BaseModel):
    """Schema for API token creation response (includes plaintext token)"""
    id: int
    name: str
    description: Optional[str]
    token: str = Field(..., description="Plaintext token - SAVE THIS, it won't be shown again")
    scopes: Optional[List[str]]
    expires_at: Optional[datetime]
    created_at: datetime
    created_by: UserSnippet
    
    class Config:
        from_attributes = True


class APITokenResponse(BaseModel):
    """Schema for API token (without plaintext token)"""
    id: int
    name: str
    description: Optional[str]
    scopes: Optional[List[str]]
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    is_active: bool
    created_at: datetime
    created_by: UserSnippet
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[UserSnippet] = None
    
    @field_validator('scopes', mode='before')
    @classmethod
    def parse_scopes(cls, v):
        """Parse scopes from JSON string to list"""
        if isinstance(v, str):
            import json
            return json.loads(v) if v else None
        return v
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "CI/CD Pipeline Token",
                "description": "Token for automated certificate generation",
                "scopes": ["certificates:read", "certificates:write"],
                "expires_at": "2027-01-03T10:00:00Z",
                "last_used_at": "2026-01-03T08:30:00Z",
                "is_active": True,
                "created_at": "2026-01-03T10:00:00Z",
                "created_by": {
                    "id": 1,
                    "username": "admin",
                    "email": "admin@example.com",
                    "full_name": "Admin User"
                }
            }
        }


class APITokenUpdate(BaseModel):
    """Schema for updating an API token"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    scopes: Optional[List[str]] = None
    is_active: Optional[bool] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "Updated Token Name",
                "description": "Updated description",
                "is_active": False
            }
        }


class TokenLoginRequest(BaseModel):
    """Schema for exchanging API token for JWT"""
    api_token: str = Field(..., description="API token to exchange for JWT")
    
    class Config:
        json_schema_extra = {
            "example": {
                "api_token": "tca_1234567890abcdef..."
            }
        }


class TokenLoginResponse(BaseModel):
    """Schema for JWT token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token expiry in seconds")
    user: UserSnippet
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "user": {
                    "id": 1,
                    "username": "admin",
                    "email": "admin@example.com",
                    "full_name": "Admin User"
                }
            }
        }