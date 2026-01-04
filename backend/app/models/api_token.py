"""
API Token Model - app/models/api_token.py
For long-lived API tokens that can be exchanged for JWTs

FIXED: Explicit foreign_keys specification for relationships
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class APIToken(Base):
    """
    API Token model for automation and scripting
    
    Tokens are hashed (bcrypt) and can be exchanged for short-lived JWT tokens.
    Only admins can create API tokens.
    """
    __tablename__ = "api_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Token identification
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    token_hash = Column(String(255), nullable=False, unique=True, index=True)  # bcrypt hash
    
    # Ownership
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="api_tokens", foreign_keys=[user_id])
    
    # Permissions (JSON array of scopes)
    scopes = Column(Text, nullable=True)  # JSON array: ["certificates:read", "certificates:write"]
    
    # Token lifecycle
    expires_at = Column(DateTime, nullable=True)  # NULL = never expires
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Audit fields
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    revoked_by = relationship("User", foreign_keys=[revoked_by_id])
    
    def __repr__(self):
        return f"<APIToken(id={self.id}, name='{self.name}', user_id={self.user_id})>"