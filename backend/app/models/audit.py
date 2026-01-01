from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Action details
    action = Column(String, nullable=False, index=True)  # e.g., "certificate_requested", "certificate_approved"
    resource_type = Column(String, nullable=False)  # e.g., "certificate", "user"
    resource_id = Column(Integer, nullable=True)
    
    # User who performed the action
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    # Additional details (JSON as text)
    details = Column(Text, nullable=True)
    
    # Request metadata
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    
    # Timestamp
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)