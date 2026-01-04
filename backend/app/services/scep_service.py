"""
SCEP Service - app/services/scep_service.py
Implements SCEP protocol (RFC 8894) for automated certificate enrollment
"""
import re
from datetime import datetime
from typing import Optional, Tuple, Dict
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from sqlalchemy.orm import Session
import httpx

from app.models.scep_client import SCEPClient
from app.models.certificate import CertificateType
from app.services.scep_client_service import SCEPClientService
from app.services.ca_service import CAService
from app.core.config import settings

logger = logging.getLogger(__name__)


class SCEPService:
    """Service for handling SCEP protocol operations"""
    
    # MAC address regex pattern
    MAC_ADDRESS_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    
    @staticmethod
    def get_ca_caps() -> str:
        """
        Get CA capabilities (GetCACaps operation)
        
        Returns supported SCEP capabilities as newline-separated string
        """
        capabilities = [
            "POSTPKIOperation",  # Support POST for PKIOperation
            "SHA-256",           # Support SHA-256 hashing
            "AES",              # Support AES encryption
            "SCEPStandard",     # RFC 8894 compliance
        ]
        
        # Add Renewal if we want to support certificate renewal
        # capabilities.append("Renewal")
        
        return "\n".join(capabilities)
    
    @staticmethod
    def get_ca_cert(ca_service: CAService) -> bytes:
        """
        Get CA certificate (GetCACert operation)
        
        Returns CA certificate in DER format
        """
        ca_cert_pem = ca_service.get_ca_certificate()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
        return ca_cert.public_bytes(serialization.Encoding.DER)
    
    @staticmethod
    def detect_certificate_type(csr: x509.CertificateSigningRequest) -> Optional[CertificateType]:
        """
        Detect certificate type based on CSR Common Name
        
        Args:
            csr: Certificate Signing Request
            
        Returns:
            CertificateType.MACHINE if CN is MAC address
            CertificateType.USER if CN is username
            None if cannot determine
        """
        # Extract Common Name from CSR subject
        cn = None
        for attribute in csr.subject:
            if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                cn = attribute.value
                break
        
        if not cn:
            logger.warning("CSR has no Common Name")
            return None
        
        # Check if CN matches MAC address pattern
        if SCEPService.MAC_ADDRESS_PATTERN.match(cn):
            logger.info(f"Detected MACHINE certificate (MAC: {cn})")
            return CertificateType.MACHINE
        else:
            logger.info(f"Detected USER certificate (Username: {cn})")
            return CertificateType.USER
    
    @staticmethod
    def normalize_mac_address(mac: str) -> str:
        """
        Normalize MAC address to standard format (uppercase with colons)
        
        Args:
            mac: MAC address in any format
            
        Returns:
            Normalized MAC address (e.g., "AA:BB:CC:DD:EE:FF")
        """
        # Remove all separators
        mac_clean = mac.replace(':', '').replace('-', '').upper()
        
        # Add colons every 2 characters
        return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
    
    @staticmethod
    async def validate_user(username: str, validation_url: str) -> Tuple[bool, str]:
        """
        Validate user against external validation endpoint
        
        Args:
            username: Username to validate
            validation_url: URL to validate against
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            async with httpx.AsyncClient(timeout=settings.SCEP_VALIDATION_TIMEOUT) as client:
                response = await client.get(
                    validation_url,
                    params={"username": username}
                )
                
                if response.status_code == 200:
                    logger.info(f"User validation successful: {username}")
                    return True, "User validated successfully"
                elif response.status_code == 404:
                    logger.warning(f"User validation failed: {username} not found")
                    return False, "User not found"
                else:
                    logger.error(f"User validation error: HTTP {response.status_code}")
                    
                    # Fail-open or fail-closed based on config
                    if settings.SCEP_ALLOW_WITHOUT_VALIDATION:
                        logger.warning("Allowing user certificate despite validation error (fail-open)")
                        return True, "Validation error, but fail-open enabled"
                    else:
                        return False, f"Validation service error: HTTP {response.status_code}"
                        
        except httpx.TimeoutException:
            logger.error(f"User validation timeout for {username}")
            if settings.SCEP_ALLOW_WITHOUT_VALIDATION:
                return True, "Validation timeout, but fail-open enabled"
            else:
                return False, "Validation service timeout"
                
        except Exception as e:
            logger.error(f"User validation exception: {str(e)}")
            if settings.SCEP_ALLOW_WITHOUT_VALIDATION:
                return True, f"Validation exception, but fail-open enabled: {str(e)}"
            else:
                return False, f"Validation service error: {str(e)}"
    
    @staticmethod
    async def validate_machine(mac_address: str, validation_url: str) -> Tuple[bool, str]:
        """
        Validate machine against external validation endpoint
        
        Args:
            mac_address: MAC address to validate (normalized)
            validation_url: URL to validate against
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            async with httpx.AsyncClient(timeout=settings.SCEP_VALIDATION_TIMEOUT) as client:
                response = await client.get(
                    validation_url,
                    params={"mac_address": mac_address}
                )
                
                if response.status_code == 200:
                    logger.info(f"Machine validation successful: {mac_address}")
                    return True, "Machine validated successfully"
                elif response.status_code == 404:
                    logger.warning(f"Machine validation failed: {mac_address} not found")
                    return False, "Machine not found"
                else:
                    logger.error(f"Machine validation error: HTTP {response.status_code}")
                    
                    # Fail-open or fail-closed based on config
                    if settings.SCEP_ALLOW_WITHOUT_VALIDATION:
                        logger.warning("Allowing machine certificate despite validation error (fail-open)")
                        return True, "Validation error, but fail-open enabled"
                    else:
                        return False, f"Validation service error: HTTP {response.status_code}"
                        
        except httpx.TimeoutException:
            logger.error(f"Machine validation timeout for {mac_address}")
            if settings.SCEP_ALLOW_WITHOUT_VALIDATION:
                return True, "Validation timeout, but fail-open enabled"
            else:
                return False, "Validation service timeout"
                
        except Exception as e:
            logger.error(f"Machine validation exception: {str(e)}")
            if settings.SCEP_ALLOW_WITHOUT_VALIDATION:
                return True, f"Validation exception, but fail-open enabled: {str(e)}"
            else:
                return False, f"Validation service error: {str(e)}"
    
    @staticmethod
    async def validate_certificate_request(
        csr: x509.CertificateSigningRequest,
        cert_type: CertificateType,
        scep_client: SCEPClient
    ) -> Tuple[bool, str]:
        """
        Validate certificate request based on type and client configuration
        
        Args:
            csr: Certificate Signing Request
            cert_type: Detected certificate type
            scep_client: SCEP client making the request
            
        Returns:
            Tuple of (is_valid, message)
        """
        # Check if client is allowed to request this certificate type
        cert_type_str = cert_type.value
        if cert_type_str not in scep_client.allowed_certificate_types:
            logger.warning(
                f"SCEP client {scep_client.id} not allowed to request {cert_type_str} certificates"
            )
            return False, f"Client not authorized to request {cert_type_str} certificates"
        
        # Extract Common Name
        cn = None
        for attribute in csr.subject:
            if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                cn = attribute.value
                break
        
        if not cn:
            return False, "CSR missing Common Name"
        
        # Validate based on certificate type
        if cert_type == CertificateType.MACHINE:
            # Normalize MAC address
            try:
                normalized_mac = SCEPService.normalize_mac_address(cn)
            except Exception as e:
                logger.error(f"Invalid MAC address format: {cn}")
                return False, f"Invalid MAC address format: {cn}"
            
            # Validate with external endpoint if configured
            if scep_client.machine_validation_url:
                return await SCEPService.validate_machine(
                    normalized_mac,
                    scep_client.machine_validation_url
                )
            else:
                # No validation URL configured, allow
                logger.info(f"No machine validation URL configured, allowing {normalized_mac}")
                return True, "No validation required"
        
        elif cert_type == CertificateType.USER:
            # Validate with external endpoint if configured
            if scep_client.user_validation_url:
                return await SCEPService.validate_user(
                    cn,
                    scep_client.user_validation_url
                )
            else:
                # No validation URL configured, allow
                logger.info(f"No user validation URL configured, allowing {cn}")
                return True, "No validation required"
        
        else:
            return False, f"Unsupported certificate type: {cert_type}"
    
    @staticmethod
    def get_common_name(csr: x509.CertificateSigningRequest) -> Optional[str]:
        """
        Extract Common Name from CSR
        
        Args:
            csr: Certificate Signing Request
            
        Returns:
            Common Name or None
        """
        for attribute in csr.subject:
            if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                return attribute.value
        return None