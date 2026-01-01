from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.schemas.user import UserSnippet


class AuditLogResponse(BaseModel):
    id: int
    action: str
    resource_type: str
    resource_id: Optional[int] = None
    user_id: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    created_at: datetime
    
    user: Optional[UserSnippet] = None
    
    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    total: int
    items: List[AuditLogResponse]