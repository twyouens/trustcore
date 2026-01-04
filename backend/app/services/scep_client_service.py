"""
SCEP Client Service - app/services/scep_client_service.py
Business logic for SCEP client management
"""
from datetime import datetime
from typing import Optional, List
from uuid import UUID
import logging

from sqlalchemy.orm import Session, joinedload

from app.models.scep_client import SCEPClient
from app.core.config import settings

logger = logging.getLogger(__name__)


class SCEPClientService:
    """Service for managing SCEP clients"""
    
    @staticmethod
    def create_client(
        db: Session,
        name: str,
        allowed_certificate_types: List[str],
        created_by_id: int,
        description: Optional[str] = None,
        user_validation_url: Optional[str] = None,
        machine_validation_url: Optional[str] = None,
        enabled: bool = True
    ) -> SCEPClient:
        """
        Create a new SCEP client
        
        Args:
            db: Database session
            name: Client name
            allowed_certificate_types: List of cert types (machine, user)
            created_by_id: ID of admin creating the client
            description: Optional description
            user_validation_url: Optional user validation endpoint
            machine_validation_url: Optional machine validation endpoint
            enabled: Whether client is enabled
            
        Returns:
            Created SCEPClient object
        """
        scep_client = SCEPClient(
            name=name,
            description=description,
            allowed_certificate_types=allowed_certificate_types,
            user_validation_url=user_validation_url,
            machine_validation_url=machine_validation_url,
            enabled=enabled,
            created_by_id=created_by_id
        )
        
        db.add(scep_client)
        db.commit()
        db.refresh(scep_client)
        
        logger.info(f"Created SCEP client '{name}' with ID {scep_client.id}")
        
        return scep_client
    
    @staticmethod
    def get_client_by_id(db: Session, client_id: UUID) -> Optional[SCEPClient]:
        """
        Get SCEP client by ID with relationships loaded
        
        Args:
            db: Database session
            client_id: Client UUID
            
        Returns:
            SCEPClient object or None
        """
        return db.query(SCEPClient).options(
            joinedload(SCEPClient.created_by)
        ).filter(SCEPClient.id == client_id).first()
    
    @staticmethod
    def get_all_clients(
        db: Session,
        include_disabled: bool = False
    ) -> List[SCEPClient]:
        """
        Get all SCEP clients
        
        Args:
            db: Database session
            include_disabled: Include disabled clients
            
        Returns:
            List of SCEPClient objects
        """
        query = db.query(SCEPClient).options(
            joinedload(SCEPClient.created_by)
        )
        
        if not include_disabled:
            query = query.filter(SCEPClient.enabled == True)
        
        return query.order_by(SCEPClient.created_at.desc()).all()
    
    @staticmethod
    def update_client(
        db: Session,
        client_id: UUID,
        name: Optional[str] = None,
        description: Optional[str] = None,
        allowed_certificate_types: Optional[List[str]] = None,
        user_validation_url: Optional[str] = None,
        machine_validation_url: Optional[str] = None,
        enabled: Optional[bool] = None
    ) -> Optional[SCEPClient]:
        """
        Update a SCEP client
        
        Args:
            db: Database session
            client_id: Client UUID
            name: New name (optional)
            description: New description (optional)
            allowed_certificate_types: New cert types (optional)
            user_validation_url: New user validation URL (optional)
            machine_validation_url: New machine validation URL (optional)
            enabled: New enabled status (optional)
            
        Returns:
            Updated SCEPClient object or None if not found
        """
        scep_client = db.query(SCEPClient).filter(SCEPClient.id == client_id).first()
        
        if not scep_client:
            return None
        
        if name is not None:
            scep_client.name = name
        if description is not None:
            scep_client.description = description
        if allowed_certificate_types is not None:
            scep_client.allowed_certificate_types = allowed_certificate_types
        if user_validation_url is not None:
            scep_client.user_validation_url = user_validation_url
        if machine_validation_url is not None:
            scep_client.machine_validation_url = machine_validation_url
        if enabled is not None:
            scep_client.enabled = enabled
        
        scep_client.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(scep_client)
        
        logger.info(f"Updated SCEP client {client_id}")
        
        return scep_client
    
    @staticmethod
    def delete_client(db: Session, client_id: UUID) -> bool:
        """
        Delete a SCEP client
        
        Args:
            db: Database session
            client_id: Client UUID
            
        Returns:
            True if deleted, False if not found
        """
        scep_client = db.query(SCEPClient).filter(SCEPClient.id == client_id).first()
        
        if not scep_client:
            return False
        
        db.delete(scep_client)
        db.commit()
        
        logger.info(f"Deleted SCEP client {client_id}")
        
        return True
    
    @staticmethod
    def increment_stats(
        db: Session,
        client_id: UUID,
        success: bool
    ) -> None:
        """
        Increment SCEP client statistics
        
        Args:
            db: Database session
            client_id: Client UUID
            success: Whether the request was successful
        """
        scep_client = db.query(SCEPClient).filter(SCEPClient.id == client_id).first()
        
        if scep_client:
            scep_client.total_requests += 1
            if success:
                scep_client.successful_requests += 1
            else:
                scep_client.failed_requests += 1
            scep_client.last_used_at = datetime.utcnow()
            db.commit()
    
    @staticmethod
    def validate_client(
        db: Session,
        client_id: UUID
    ) -> Optional[SCEPClient]:
        """
        Validate that a SCEP client exists and is enabled
        
        Args:
            db: Database session
            client_id: Client UUID
            
        Returns:
            SCEPClient object if valid, None otherwise
        """
        scep_client = db.query(SCEPClient).filter(
            SCEPClient.id == client_id,
            SCEPClient.enabled == True
        ).first()
        
        if not scep_client:
            logger.warning(f"Invalid or disabled SCEP client: {client_id}")
            return None
        
        return scep_client
    
    @staticmethod
    def get_client_stats(db: Session) -> List[dict]:
        """
        Get statistics for all SCEP clients
        
        Args:
            db: Database session
            
        Returns:
            List of client statistics
        """
        clients = db.query(SCEPClient).all()
        
        stats = []
        for client in clients:
            success_rate = 0
            if client.total_requests > 0:
                success_rate = (client.successful_requests / client.total_requests) * 100
            
            stats.append({
                "id": client.id,
                "name": client.name,
                "total_requests": client.total_requests,
                "successful_requests": client.successful_requests,
                "failed_requests": client.failed_requests,
                "success_rate": round(success_rate, 2),
                "last_used_at": client.last_used_at
            })
        
        return stats

scep_client_service = SCEPClientService()