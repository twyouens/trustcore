"""
Certificate format conversion utilities
Handles conversion between PEM, PKCS12, DER, and PKCS7 formats
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Optional, List
from app.core.logging import get_logger

logger = get_logger(__name__)


class CertificateFormatter:
    """Utility class for converting certificates between formats"""
    
    @staticmethod
    def to_pkcs12(
        private_key_pem: str,
        certificate_pem: str,
        password: str,
        ca_cert_pem: Optional[str] = None,
        friendly_name: Optional[str] = None
    ) -> bytes:
        """
        Convert PEM certificate and key to PKCS12 format
        
        Args:
            private_key_pem: Private key in PEM format
            certificate_pem: Certificate in PEM format
            password: Password to encrypt the PKCS12 file
            ca_cert_pem: Optional CA certificate to include in the bundle
            friendly_name: Optional friendly name for the certificate
            
        Returns:
            PKCS12 data as bytes
        """
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Load certificate
        cert = x509.load_pem_x509_certificate(
            certificate_pem.encode(),
            backend=default_backend()
        )
        
        # Load CA certificate if provided
        ca_certs = []
        if ca_cert_pem:
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_pem.encode(),
                backend=default_backend()
            )
            ca_certs.append(ca_cert)
        
        # Create PKCS12
        p12_data = pkcs12.serialize_key_and_certificates(
            name=friendly_name.encode() if friendly_name else None,
            key=private_key,
            cert=cert,
            cas=ca_certs if ca_certs else None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        return p12_data
    
    @staticmethod
    def to_der(certificate_pem: str) -> bytes:
        """
        Convert PEM certificate to DER format
        
        Args:
            certificate_pem: Certificate in PEM format
            
        Returns:
            DER encoded certificate as bytes
        """
        cert = x509.load_pem_x509_certificate(
            certificate_pem.encode(),
            backend=default_backend()
        )
        
        return cert.public_bytes(serialization.Encoding.DER)
    
    @staticmethod
    def to_pkcs7(
        certificate_pem: str,
        ca_cert_pem: Optional[str] = None,
        include_chain: bool = True
    ) -> bytes:
        """
        Convert PEM certificate to PKCS7 format (degenerate - certificates only)
        
        Used for SCEP responses and certificate distribution.
        
        Args:
            certificate_pem: Certificate in PEM format
            ca_cert_pem: Optional CA certificate to include in chain
            include_chain: Whether to include CA certificate in chain
            
        Returns:
            PKCS7 data as bytes (DER encoded)
        """
        # Load certificate
        cert = x509.load_pem_x509_certificate(
            certificate_pem.encode(),
            backend=default_backend()
        )
        
        # Build certificate list
        certs = [cert]
        
        # Add CA certificate if provided and requested
        if include_chain and ca_cert_pem:
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_pem.encode(),
                backend=default_backend()
            )
            certs.append(ca_cert)
        
        # Serialize as PKCS7 (degenerate - no signed data, just certs)
        pkcs7_data = pkcs7.serialize_certificates(
            certs,
            serialization.Encoding.DER
        )
        
        return pkcs7_data
    
    @staticmethod
    def from_pkcs7(pkcs7_data: bytes) -> List[str]:
        """
        Extract certificates from PKCS7 data
        
        Args:
            pkcs7_data: PKCS7 data (DER or PEM encoded)
            
        Returns:
            List of certificates in PEM format
        """
        try:
            # Try to load as DER
            certs = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
        except:
            try:
                # Try to load as PEM
                certs = pkcs7.load_pem_pkcs7_certificates(pkcs7_data)
            except Exception as e:
                logger.error(f"Failed to load PKCS7 data: {str(e)}")
                return []
        
        # Convert to PEM
        cert_pems = []
        for cert in certs:
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            cert_pems.append(cert_pem)
        
        return cert_pems
    
    @staticmethod
    def unwrap_pkcs7_csr(pkcs7_data: bytes) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract CSR from PKCS7 signed data (for SCEP)
        
        SCEP clients wrap CSRs in PKCS#7 SignedData structures.
        This method also accepts plain PEM/DER CSRs for backward compatibility.
        
        Args:
            pkcs7_data: PKCS7 message bytes or plain CSR
            
        Returns:
            Tuple of (csr_pem, error_message)
            If successful: (csr_pem, None)
            If failed: (None, error_message)
        """
        # Try to parse as direct PEM CSR first (most common for testing)
        try:
            csr_pem_str = pkcs7_data.decode('utf-8')
            if '-----BEGIN CERTIFICATE REQUEST-----' in csr_pem_str:
                # Validate it's a proper CSR
                x509.load_pem_x509_csr(csr_pem_str.encode(), default_backend())
                logger.info("Accepted direct PEM CSR")
                return csr_pem_str, None
        except:
            pass
        
        # Try to parse as direct DER CSR
        try:
            csr = x509.load_der_x509_csr(pkcs7_data, default_backend())
            csr_pem_str = csr.public_bytes(serialization.Encoding.PEM).decode()
            logger.info("Accepted direct DER CSR")
            return csr_pem_str, None
        except:
            pass
        
        # Try to extract CSR from PKCS7 wrapper
        try:
            # Convert to string to search for CSR markers
            data_str = pkcs7_data.decode('utf-8', errors='ignore')
            
            # Look for CSR markers within PKCS7
            csr_start = "-----BEGIN CERTIFICATE REQUEST-----"
            csr_end = "-----END CERTIFICATE REQUEST-----"
            
            if csr_start in data_str and csr_end in data_str:
                start_idx = data_str.index(csr_start)
                end_idx = data_str.index(csr_end) + len(csr_end)
                csr_pem = data_str[start_idx:end_idx]
                
                # Validate it's a proper CSR
                x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
                logger.info("Extracted CSR from PKCS7 wrapper")
                return csr_pem, None
        except Exception as e:
            logger.debug(f"Could not extract CSR from PKCS7: {str(e)}")
        
        return None, "Invalid PKCS7 or CSR format. Expected PEM/DER CSR or PKCS7-wrapped CSR."
    
    @staticmethod
    def split_pem_bundle(pem_bundle: str) -> Tuple[str, str]:
        """
        Split a PEM bundle into private key and certificate
        
        Args:
            pem_bundle: PEM bundle containing both key and certificate
            
        Returns:
            Tuple of (private_key_pem, certificate_pem)
        """
        # Extract private key
        private_key_start = pem_bundle.find('-----BEGIN PRIVATE KEY-----')
        private_key_end = pem_bundle.find('-----END PRIVATE KEY-----') + len('-----END PRIVATE KEY-----')
        
        if private_key_start == -1 or private_key_end == -1:
            # Try RSA private key format
            private_key_start = pem_bundle.find('-----BEGIN RSA PRIVATE KEY-----')
            private_key_end = pem_bundle.find('-----END RSA PRIVATE KEY-----') + len('-----END RSA PRIVATE KEY-----')
        
        private_key_pem = pem_bundle[private_key_start:private_key_end].strip()
        
        # Extract certificate
        cert_start = pem_bundle.find('-----BEGIN CERTIFICATE-----')
        cert_end = pem_bundle.find('-----END CERTIFICATE-----') + len('-----END CERTIFICATE-----')
        certificate_pem = pem_bundle[cert_start:cert_end].strip()
        
        return private_key_pem, certificate_pem
    
    @staticmethod
    def get_media_type(format_type: str) -> str:
        """Get MIME type for certificate format"""
        media_types = {
            'pem': 'application/x-pem-file',
            'pkcs12': 'application/x-pkcs12',
            'pkcs7': 'application/x-x509-ca-ra-cert',
            'der': 'application/x-x509-ca-cert',
            'p12': 'application/x-pkcs12',
            'p7b': 'application/x-x509-ca-ra-cert',
        }
        return media_types.get(format_type.lower(), 'application/octet-stream')
    
    @staticmethod
    def get_file_extension(format_type: str) -> str:
        """Get file extension for certificate format"""
        extensions = {
            'pem': 'pem',
            'pkcs12': 'p12',
            'pkcs7': 'p7b',
            'der': 'der',
            'p12': 'p12',
            'p7b': 'p7b',
        }
        return extensions.get(format_type.lower(), 'bin')


certificate_formatter = CertificateFormatter()