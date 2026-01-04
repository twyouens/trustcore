"""
SCEP Client Model - app/models/scep_client.py
Model for SCEP client registration and management
"""
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
import uuid
from app.core.config import settings

from app.core.database import Base


class SCEPClient(Base):
    """
    SCEP Client model for MDM integration
    
    Each SCEP client represents an MDM or automated system that can
    request certificates via SCEP protocol. The client ID is used in
    the SCEP URL for authentication.
    """
    __tablename__ = "scep_clients"
    
    # UUID primary key (used in SCEP URL)
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Client identification
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Permissions
    allowed_certificate_types = Column(
        ARRAY(String),
        nullable=False,
        comment="Certificate types this client can request: machine, user"
    )
    
    # Validation endpoints (optional)
    user_validation_url = Column(
        String(500),
        nullable=True,
        comment="URL to validate user certificates (GET with ?username=X)"
    )
    machine_validation_url = Column(
        String(500),
        nullable=True,
        comment="URL to validate machine certificates (GET with ?mac_address=X)"
    )
    
    # Client status
    enabled = Column(Boolean, default=True, nullable=False)
    
    # Statistics
    total_requests = Column(Integer, default=0, nullable=False)
    successful_requests = Column(Integer, default=0, nullable=False)
    failed_requests = Column(Integer, default=0, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    
    # Audit fields
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_by = relationship("User", foreign_keys=[created_by_id])
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<SCEPClient(id={self.id}, name='{self.name}')>"
    
    @property
    def scep_url(self) -> str:
        """Generate the SCEP URL for this client"""
        from app.core.config import settings
        return f"{settings.API_BASE_URL}/api/v1/scep/{self.id}/pkiclient.exe"