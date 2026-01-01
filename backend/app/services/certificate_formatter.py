"""
Certificate format conversion utilities
Handles conversion between PEM, PKCS12, and DER formats
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Optional


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
            'der': 'application/x-x509-ca-cert',
            'p12': 'application/x-pkcs12',
        }
        return media_types.get(format_type.lower(), 'application/octet-stream')
    
    @staticmethod
    def get_file_extension(format_type: str) -> str:
        """Get file extension for certificate format"""
        extensions = {
            'pem': 'pem',
            'pkcs12': 'p12',
            'der': 'der',
            'p12': 'p12',
        }
        return extensions.get(format_type.lower(), 'bin')


certificate_formatter = CertificateFormatter()