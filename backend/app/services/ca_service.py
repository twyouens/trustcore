import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from app.core.config import settings
from app.models.certificate import CertificateType
from app.core.logging import get_logger
import secrets

logger = get_logger(__name__)

class CAService:
    def __init__(self):
        self.storage_path = Path(settings.CA_STORAGE_PATH)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.ca_key_path = self.storage_path / settings.CA_KEY_FILE
        self.ca_cert_path = self.storage_path / settings.CA_CERT_FILE
        self.crl_path = self.storage_path / settings.CRL_FILE
        
        self._ca_key = None
        self._ca_cert = None
    
    def initialize_ca(self) -> None:
        """Initialize the CA if it doesn't exist"""
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            logger.info("CA already initialized")
            return

        logger.info("Initializing Certificate Authority...")

        # Generate CA private key
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=settings.CA_KEY_SIZE,
            backend=default_backend()
        )
        
        # Create CA certificate
        subject_attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, settings.CA_COUNTRY),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, settings.CA_STATE),
            x509.NameAttribute(NameOID.LOCALITY_NAME, settings.CA_LOCALITY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.CA_ORGANIZATION),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, settings.CA_ORGANIZATIONAL_UNIT),
            x509.NameAttribute(NameOID.COMMON_NAME, settings.CA_NAME),
        ]
        
        # Only add email if provided
        if settings.CA_EMAIL:
            subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, settings.CA_EMAIL))
        
        subject = issuer = x509.Name(subject_attributes)
        
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=settings.CA_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), backend=default_backend())
        )
        
        # Save CA private key (encrypted)
        with open(self.ca_key_path, "wb") as f:
            f.write(
                ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                    # TODO: Add password protection in production
                )
            )
        
        # Save CA certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
        # Set proper permissions
        os.chmod(self.ca_key_path, 0o600)
        os.chmod(self.ca_cert_path, 0o644)

        logger.info("CA initialized successfully")
        logger.info(f"CA Certificate: {self.ca_cert_path}")
        logger.info(f"CA Private Key: {self.ca_key_path}")

    def load_ca(self) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Load CA private key and certificate"""
        if self._ca_key and self._ca_cert:
            return self._ca_key, self._ca_cert
        
        if not self.ca_key_path.exists() or not self.ca_cert_path.exists():
            logger.error("CA not initialized. Run initialize_ca() first.")
            raise FileNotFoundError("CA not initialized. Run initialize_ca() first.")
        
        # Load private key
        with open(self.ca_key_path, "rb") as f:
            self._ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load certificate
        with open(self.ca_cert_path, "rb") as f:
            self._ca_cert = x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
        
        return self._ca_key, self._ca_cert
    
    def get_ca_certificate(self) -> str:
        """Get CA certificate in PEM format"""
        _, ca_cert = self.load_ca()
        return ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    
    def generate_machine_certificate(
        self,
        mac_address: str,
        validity_days: int = None
    ) -> Tuple[str, str]:
        """
        Generate a machine certificate for EAP-TLS authentication
        Returns: (private_key_pem, certificate_pem)
        """
        ca_key, ca_cert = self.load_ca()
        
        if validity_days is None:
            validity_days = settings.DEFAULT_CERT_VALIDITY_DAYS
        
        # Generate private key for the certificate
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=settings.DEFAULT_KEY_SIZE,
            backend=default_backend()
        )
        
        # Create subject with MAC address as CN
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.CA_ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, mac_address),
        ])
        
        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), backend=default_backend())
        )
        
        # Convert to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        
        return private_key_pem, cert_pem
    
    def generate_user_certificate(
        self,
        username: str,
        validity_days: int = None
    ) -> Tuple[str, str]:
        """
        Generate a user certificate for EAP-TLS authentication
        Returns: (private_key_pem, certificate_pem)
        """
        ca_key, ca_cert = self.load_ca()
        
        if validity_days is None:
            validity_days = settings.DEFAULT_CERT_VALIDITY_DAYS
        
        # Generate private key for the certificate
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=settings.DEFAULT_KEY_SIZE,
            backend=default_backend()
        )
        
        # Create subject with username as CN
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.CA_ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
        
        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), backend=default_backend())
        )
        
        # Convert to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        
        return private_key_pem, cert_pem
    
    def sign_csr(
        self,
        csr_pem: str,
        validity_days: int = None,
        cert_type: CertificateType = CertificateType.SERVER
    ) -> str:
        """
        Sign a Certificate Signing Request
        Returns: certificate_pem
        """
        ca_key, ca_cert = self.load_ca()
        
        if validity_days is None:
            validity_days = settings.DEFAULT_CERT_VALIDITY_DAYS
        
        # Load CSR
        csr = x509.load_pem_x509_csr(csr_pem.encode(), backend=default_backend())
        
        # Validate CSR signature
        if not csr.is_signature_valid:
            logger.error("Invalid CSR signature")
            raise ValueError("Invalid CSR signature")
        
        # Build certificate from CSR
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        )
        
        # Add extensions based on certificate type
        if cert_type == CertificateType.SERVER:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=True,
            )
        
        # Copy SANs from CSR if present
        try:
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            builder = builder.add_extension(san_ext.value, critical=False)
        except x509.ExtensionNotFound:
            pass
        
        # Add key identifiers
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        
        # Sign certificate
        cert = builder.sign(ca_key, hashes.SHA256(), backend=default_backend())
        
        # Convert to PEM format
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        
        return cert_pem
    
    def validate_csr(self, csr_pem: str) -> Tuple[bool, Optional[str], Optional[List[str]]]:
        """
        Validate a CSR
        Returns: (is_valid, error_message, subject_alternative_names)
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode(), backend=default_backend())
            
            # Check signature
            if not csr.is_signature_valid:
                logger.error("Invalid CSR signature")
                return False, "Invalid CSR signature", None
            
            # Check key size for RSA keys
            public_key = csr.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                if key_size < 2048:
                    logger.error(f"Key size {key_size} is too small (minimum 2048 bits)")
                    return False, f"Key size {key_size} is too small (minimum 2048 bits)", None
            
            # Extract SANs if present
            sans = None
            try:
                san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = [name.value for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass
            
            return True, None, sans
            
        except Exception as e:
            return False, str(e), None
    
    def generate_crl(self, revoked_certificates: List[Tuple[int, datetime]]) -> str:
        """
        Generate Certificate Revocation List
        revoked_certificates: List of (serial_number, revocation_date) tuples
        Returns: CRL in PEM format
        """
        ca_key, ca_cert = self.load_ca()
        
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(datetime.utcnow())
        builder = builder.next_update(datetime.utcnow() + timedelta(hours=settings.CRL_UPDATE_HOURS))
        
        # Add revoked certificates
        for serial_number, revocation_date in revoked_certificates:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial_number)
                .revocation_date(revocation_date)
                .build(default_backend())
            )
            builder = builder.add_revoked_certificate(revoked_cert)
        
        # Sign CRL
        crl = builder.sign(ca_key, hashes.SHA256(), backend=default_backend())
        
        # Save to file
        crl_pem = crl.public_bytes(serialization.Encoding.PEM)
        with open(self.crl_path, "wb") as f:
            f.write(crl_pem)
        
        return crl_pem.decode()
    
    def get_crl(self) -> Optional[str]:
        """Get current CRL in PEM format"""
        if not self.crl_path.exists():
            return None
        
        with open(self.crl_path, "rb") as f:
            return f.read().decode()


# Singleton instance
ca_service = CAService()