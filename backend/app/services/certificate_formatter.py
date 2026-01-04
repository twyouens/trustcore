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
        Extract CSR from SCEP PKCS#7 message
        
        Real SCEP structure (sscep):
        1. Outer: SignedData (client signature for authentication)
        2. Inner: EnvelopedData (encrypted with CA public key)
        3. Inside: The actual CSR
        
        Args:
            pkcs7_data: PKCS7 message bytes or plain CSR
            
        Returns:
            Tuple of (csr_pem, error_message)
        """
        # Try direct PEM CSR first (testing)
        try:
            csr_pem_str = pkcs7_data.decode('utf-8')
            if '-----BEGIN CERTIFICATE REQUEST-----' in csr_pem_str:
                x509.load_pem_x509_csr(csr_pem_str.encode(), default_backend())
                logger.debug("Accepted direct PEM CSR")
                return csr_pem_str, None
        except:
            pass
        
        # Try direct DER CSR (testing)
        try:
            csr = x509.load_der_x509_csr(pkcs7_data, default_backend())
            csr_pem_str = csr.public_bytes(serialization.Encoding.PEM).decode()
            logger.debug("Accepted direct DER CSR")
            return csr_pem_str, None
        except:
            pass
        
        # Parse SCEP PKCS#7 message
        try:
            import asn1crypto.cms
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from app.services.ca_service import CAService
            
            # Load as ContentInfo
            content_info = asn1crypto.cms.ContentInfo.load(pkcs7_data)
            content_type = content_info['content_type'].native
            
            logger.debug(f"PKCS#7 content type: {content_type}")
            
            # Handle SignedData (outer layer)
            if content_type == 'signed_data':
                signed_data = content_info['content']
                encap_content = signed_data['encap_content_info']
                
                if encap_content['content'] is None:
                    return None, "No encapsulated content in SignedData"
                
                content_bytes = bytes(encap_content['content'])
                logger.debug(f"SignedData encapsulated content: {len(content_bytes)} bytes")
                
                # Check if it's nested PKCS#7 (starts with SEQUENCE tag 0x30)
                if content_bytes[0] == 0x30:
                    logger.debug("Detected nested PKCS#7 structure")
                    
                    # Parse inner ContentInfo
                    try:
                        inner_content_info = asn1crypto.cms.ContentInfo.load(content_bytes)
                        inner_type = inner_content_info['content_type'].native
                        logger.debug(f"Inner PKCS#7 type: {inner_type}")
                        
                        # Inner should be EnvelopedData
                        if inner_type == 'enveloped_data':
                            # Recursively decrypt EnvelopedData
                            return CertificateFormatter.unwrap_pkcs7_csr(content_bytes)
                        else:
                            # Try parsing inner content directly
                            return CertificateFormatter.unwrap_pkcs7_csr(content_bytes)
                            
                    except Exception as e:
                        logger.warning(f"Failed to parse as nested PKCS#7: {str(e)}")
                
                # Try direct CSR
                try:
                    csr = x509.load_der_x509_csr(content_bytes, default_backend())
                    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
                    logger.debug(f"✓ Extracted CSR from SignedData: {csr.subject}")
                    return csr_pem, None
                except Exception as e:
                    logger.error(f"Content is not a CSR: {str(e)}")
                    return None, f"SignedData content is not a valid CSR: {str(e)}"
            
            # Handle EnvelopedData (encrypted layer)
            elif content_type == 'enveloped_data':
                logger.debug("Decrypting EnvelopedData")
                
                enveloped_data = content_info['content']
                encrypted_content = enveloped_data['encrypted_content_info']
                encrypted_data = bytes(encrypted_content['encrypted_content'])
                
                logger.debug(f"Encrypted data: {len(encrypted_data)} bytes")
                
                # Get recipient info
                recipient_infos = enveloped_data['recipient_infos']
                if len(recipient_infos) == 0:
                    return None, "No recipient info in EnvelopedData"
                
                recipient = recipient_infos[0].chosen
                encrypted_key = bytes(recipient['encrypted_key'])
                
                logger.info(f"Encrypted key: {len(encrypted_key)} bytes")
                
                # Decrypt using CA private key
                ca_service = CAService()
                ca_key = ca_service._load_ca_key()
                
                try:
                    symmetric_key = ca_key.decrypt(encrypted_key, padding.PKCS1v15())
                    logger.debug(f"Decrypted symmetric key: {len(symmetric_key)} bytes")
                except Exception as e:
                    logger.error(f"Failed to decrypt symmetric key: {str(e)}")
                    return None, f"Decryption failed: {str(e)}"
                
                # Get encryption algorithm
                enc_alg = encrypted_content['content_encryption_algorithm']
                enc_alg_oid = enc_alg['algorithm'].native
                
                logger.debug(f"Encryption algorithm: {enc_alg_oid}")
                
                # Decrypt content
                if 'des-ede3-cbc' in enc_alg_oid:
                    # 3DES-CBC
                    iv = bytes(enc_alg['parameters'])
                    cipher = Cipher(
                        algorithms.TripleDES(symmetric_key),
                        modes.CBC(iv),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                    
                    # Remove PKCS7 padding
                    padding_len = decrypted_data[-1]
                    decrypted_data = decrypted_data[:-padding_len]
                    
                    logger.debug(f"Decrypted (3DES): {len(decrypted_data)} bytes")
                    
                elif 'aes' in enc_alg_oid.lower():
                    # AES-CBC
                    iv = bytes(enc_alg['parameters'])
                    
                    if '128' in enc_alg_oid:
                        algorithm = algorithms.AES128(symmetric_key[:16])
                    elif '256' in enc_alg_oid:
                        algorithm = algorithms.AES256(symmetric_key[:32])
                    else:
                        algorithm = algorithms.AES(symmetric_key)
                    
                    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                    
                    # Remove PKCS7 padding
                    padding_len = decrypted_data[-1]
                    decrypted_data = decrypted_data[:-padding_len]
                    
                    logger.info(f"Decrypted (AES): {len(decrypted_data)} bytes")
                else:
                    return None, f"Unsupported encryption algorithm: {enc_alg_oid}"
                
                # Parse decrypted content - could be CSR or another PKCS#7 layer
                logger.debug(f"Decrypted data starts with: {decrypted_data[:20].hex()}")
                
                # Try as CSR first
                try:
                    csr = x509.load_der_x509_csr(decrypted_data, default_backend())
                    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
                    logger.debug(f"✓ Extracted CSR from EnvelopedData: {csr.subject}")
                    return csr_pem, None
                except:
                    # Try as nested PKCS#7
                    logger.info("Decrypted content is not direct CSR, trying nested parse")
                    return CertificateFormatter.unwrap_pkcs7_csr(decrypted_data)
            
            return None, f"Unsupported PKCS#7 content type: {content_type}"
            
        except Exception as e:
            logger.error(f"Failed to parse PKCS#7: {str(e)}", exc_info=True)
            return None, f"PKCS#7 parsing error: {str(e)}"

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
    
    @staticmethod
    def create_scep_cert_response(
        cert_pem: str,
        ca_cert_pem: str,
        recipient_cert_pem: str,
        transaction_id: str,
        recipient_nonce: bytes
    ) -> bytes:
        """
        Create SCEP PKIOperation response
        
        Structure: SignedData(EnvelopedData(SignedData(certs)))
        
        Args:
            cert_pem: Issued certificate in PEM format
            ca_cert_pem: CA certificate in PEM format
            recipient_cert_pem: Client's self-signed certificate
            
        Returns:
            PKCS#7 SignedData in DER format
        """
        try:
            import asn1crypto.cms
            import asn1crypto.core
            from asn1crypto import x509 as asn1_x509
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            from app.services.ca_service import CAService
            import os
            
            logger.info("Creating SCEP response (SignedData wrapping EnvelopedData)")
            
            # Load certificates
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
            recipient_cert = x509.load_pem_x509_certificate(recipient_cert_pem.encode(), default_backend())
            
            # Convert to ASN1
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            ca_cert_der = ca_cert.public_bytes(serialization.Encoding.DER)
            
            cert_asn1 = asn1_x509.Certificate.load(cert_der)
            ca_cert_asn1 = asn1_x509.Certificate.load(ca_cert_der)

            # sender Nonce
            sender_nonce = os.urandom(16)
            
            # Step 1: Create inner degenerate SignedData with certificates
            inner_signed_data = asn1crypto.cms.SignedData({
                'version': 'v1',
                'digest_algorithms': asn1crypto.cms.DigestAlgorithms([]),
                'encap_content_info': asn1crypto.cms.ContentInfo({
                    'content_type': 'data',
                    'content': None
                }),
                'certificates': asn1crypto.cms.CertificateSet([
                    asn1crypto.cms.CertificateChoices(name='certificate', value=cert_asn1),
                    asn1crypto.cms.CertificateChoices(name='certificate', value=ca_cert_asn1)
                ]),
                'signer_infos': asn1crypto.cms.SignerInfos([])
            })
            
            inner_content_info = asn1crypto.cms.ContentInfo({
                'content_type': 'signed_data',
                'content': inner_signed_data
            })
            
            inner_der = inner_content_info.dump()
            logger.debug(f"Inner SignedData (certs): {len(inner_der)} bytes")

            # Step 2: Encrypt to recipient -> EnvelopedData
            recipient_public_key = recipient_cert.public_key()
            
            symmetric_key = os.urandom(24)  # 3DES = 24 bytes
            iv = os.urandom(8)
            
            # Encrypt with 3DES
            cipher = Cipher(TripleDES(symmetric_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Add PKCS7 padding
            block_size = 8
            padding_len = block_size - (len(inner_der) % block_size)
            padded_data = inner_der + bytes([padding_len] * padding_len)
            
            encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
            
            # Encrypt symmetric key
            encrypted_key = recipient_public_key.encrypt(symmetric_key, padding.PKCS1v15())
            
            logger.debug(f"Encrypted content: {len(encrypted_content)} bytes")
            
            # Create RecipientInfo
            recipient_asn1 = asn1_x509.Certificate.load(
                recipient_cert.public_bytes(serialization.Encoding.DER)
            )
            
            recipient_info = asn1crypto.cms.RecipientInfo({
                'ktri': asn1crypto.cms.KeyTransRecipientInfo({
                    'version': 'v0',
                    'rid': asn1crypto.cms.RecipientIdentifier({
                        'issuer_and_serial_number': asn1crypto.cms.IssuerAndSerialNumber({
                            'issuer': recipient_asn1['tbs_certificate']['issuer'],
                            'serial_number': recipient_asn1['tbs_certificate']['serial_number']
                        })
                    }),
                    'key_encryption_algorithm': asn1crypto.cms.KeyEncryptionAlgorithm({
                        'algorithm': 'rsa'
                    }),
                    'encrypted_key': asn1crypto.core.OctetString(encrypted_key)
                })
            })
            
            # Create EnvelopedData
            enveloped_data = asn1crypto.cms.EnvelopedData({
                'version': 'v0',
                'recipient_infos': asn1crypto.cms.RecipientInfos([recipient_info]),
                'encrypted_content_info': asn1crypto.cms.EncryptedContentInfo({
                    'content_type': 'data',
                    'content_encryption_algorithm': asn1crypto.cms.EncryptionAlgorithm({
                        'algorithm': '1.2.840.113549.3.7',  # des-ede3-cbc
                        'parameters': asn1crypto.core.OctetString(iv)
                    }),
                    'encrypted_content': asn1crypto.core.OctetString(encrypted_content)
                })
            })
            
            enveloped_content_info = asn1crypto.cms.ContentInfo({
                'content_type': 'enveloped_data',
                'content': enveloped_data
            })
            
            enveloped_der = enveloped_content_info.dump()
            logger.debug(f"EnvelopedData: {len(enveloped_der)} bytes")
            
            # Step 3: Wrap in outer SignedData (signed by CA)
            ca_service = CAService()
            ca_key = ca_service._load_ca_key()
            
            # Compute SHA-256 hash of EnvelopedData for signed attributes
            digest_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest_obj.update(enveloped_der)
            message_digest = digest_obj.finalize()
            
            logger.debug(f"Message digest: {message_digest.hex()}")
            
            # Create signed attributes (REQUIRED for proper signature verification)
            logger.debug(f"Creating signed attributes with transaction ID: {transaction_id}")
            logger.debug(f"Generated senderNonce: {sender_nonce.hex()}")
            logger.debug(f"Using recipientNonce: {recipient_nonce.hex() if recipient_nonce else 'None'}")
            signed_attrs = asn1crypto.cms.CMSAttributes([
                asn1crypto.cms.CMSAttribute({
                    'type': '1.2.840.113549.1.9.3',  # content-type
                    'values': ['1.2.840.113549.1.7.1']
                }),
                asn1crypto.cms.CMSAttribute({
                    'type': '1.2.840.113549.1.9.4',  # message-digest
                    'values': [asn1crypto.core.OctetString(message_digest)]
                }),
                asn1crypto.cms.CMSAttribute({
                    'type': '2.16.840.1.113733.1.9.7',  # transactionId
                    'values': [asn1crypto.core.PrintableString(transaction_id)]
                }),
                asn1crypto.cms.CMSAttribute({
                    'type': '2.16.840.1.113733.1.9.2',  # messageType (NEW)
                    'values': [asn1crypto.core.PrintableString('3')]  # 3 = CertRep
                }),
                asn1crypto.cms.CMSAttribute({
                    'type': '2.16.840.1.113733.1.9.3',  # pkiStatus (NEW)
                    'values': [asn1crypto.core.PrintableString('0')]  # 0 = SUCCESS
                }),
                asn1crypto.cms.CMSAttribute({
                    'type': '2.16.840.1.113733.1.9.5',  # senderNonce (NEW)
                    'values': [asn1crypto.core.OctetString(sender_nonce)]
                }),
                asn1crypto.cms.CMSAttribute({
                    'type': '2.16.840.1.113733.1.9.6',  # recipientNonce (NEW)
                    'values': [asn1crypto.core.OctetString(recipient_nonce)]
                })
            ])

            # Encode signed attributes for signing
            # CRITICAL: Must use SET tag (0x31), not SEQUENCE tag (0x30)
            signed_attrs_bytes = signed_attrs.dump()
            signed_attrs_for_signing = b'\x31' + signed_attrs_bytes[1:]
            
            logger.debug(f"Signed attributes for signing: {len(signed_attrs_for_signing)} bytes")
            
            # Sign the DER-encoded signed attributes (not the content!)
            signature = ca_key.sign(
                signed_attrs_for_signing,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            logger.debug(f"CA signature: {len(signature)} bytes")
            
            # Create SignerInfo
            signer_info = asn1crypto.cms.SignerInfo({
                'version': 'v1',
                'sid': asn1crypto.cms.SignerIdentifier({
                    'issuer_and_serial_number': asn1crypto.cms.IssuerAndSerialNumber({
                        'issuer': ca_cert_asn1['tbs_certificate']['issuer'],
                        'serial_number': ca_cert_asn1['tbs_certificate']['serial_number']
                    })
                }),
                'digest_algorithm': asn1crypto.cms.DigestAlgorithm({
                    'algorithm': 'sha256'
                }),
                'signed_attrs': signed_attrs,
                'signature_algorithm': asn1crypto.cms.SignedDigestAlgorithm({
                    'algorithm': 'sha256_rsa'
                }),
                'signature': asn1crypto.core.OctetString(signature),
                'unsigned_attrs': None
            })
            
            # Create outer SignedData
            outer_signed_data = asn1crypto.cms.SignedData({
                'version': 'v1',
                'digest_algorithms': asn1crypto.cms.DigestAlgorithms([
                    asn1crypto.cms.DigestAlgorithm({'algorithm': 'sha256'})
                ]),
                'encap_content_info': asn1crypto.cms.ContentInfo({
                    'content_type': 'data',
                    'content': asn1crypto.core.OctetString(enveloped_der)
                }),
                'certificates': asn1crypto.cms.CertificateSet([
                    asn1crypto.cms.CertificateChoices(name='certificate', value=ca_cert_asn1)
                ]),
                'signer_infos': asn1crypto.cms.SignerInfos([signer_info])
            })
            
            # Wrap in ContentInfo
            outer_content_info = asn1crypto.cms.ContentInfo({
                'content_type': 'signed_data',
                'content': outer_signed_data
            })
            
            result = outer_content_info.dump()
            logger.info(f"Final SCEP response: {len(result)} bytes")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create SCEP response: {str(e)}", exc_info=True)
            raise
    
    @staticmethod
    def extract_client_cert_from_scep(pkcs7_data: bytes) -> Optional[str]:
        """Extract client's self-signed certificate from SCEP request"""
        try:
            import asn1crypto.cms
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            
            content_info = asn1crypto.cms.ContentInfo.load(pkcs7_data)
            
            if content_info['content_type'].native == 'signed_data':
                signed_data = content_info['content']
                
                # Get certificates from the SignedData
                if signed_data['certificates'] is not None:
                    for cert_choice in signed_data['certificates']:
                        # This is the client's self-signed cert
                        cert_der = cert_choice.chosen.dump()
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
                        
                        logger.info(f"Extracted client cert: {cert.subject}")
                        return cert_pem
            
            return None
        except Exception as e:
            logger.error(f"Failed to extract client cert: {str(e)}")
            return None
    
    @staticmethod
    def extract_transaction_id_from_scep(pkcs7_data: bytes) -> str:
        """Extract transactionId from SCEP request (outer SignedData)"""
        try:
            import asn1crypto.cms
            
            content_info = asn1crypto.cms.ContentInfo.load(pkcs7_data)
            
            if content_info['content_type'].native == 'signed_data':
                signed_data = content_info['content']
                
                # Check signer_infos for signed attributes
                signer_infos = signed_data['signer_infos']
                
                if signer_infos and len(signer_infos) > 0:
                    signer = signer_infos[0]
                    
                    logger.debug(f"Signer version: {signer['version'].native}")
                    logger.debug(f"Has signed_attrs: {signer['signed_attrs'] is not None}")
                    
                    if signer['signed_attrs'] is not None:
                        for attr in signer['signed_attrs']:
                            attr_type = attr['type'].native
                            logger.debug(f"Found attribute: {attr_type}")
                            
                            # TransactionId OID: 1.2.840.113549.1.9.7
                            if attr_type == '1.2.840.113549.1.9.7':
                                # Get the first value
                                trans_id_value = attr['values'][0]
                                
                                # Convert to string
                                if hasattr(trans_id_value, 'native'):
                                    trans_id = trans_id_value.native
                                else:
                                    trans_id = str(trans_id_value)
                                
                                logger.info(f"Extracted transactionId: {trans_id}")
                                return trans_id
                            
                            # Also check for SCEP-specific attributes (different OID)
                            # Some SCEP implementations use 2.16.840.1.113733.1.9.7
                            if attr_type == '2.16.840.1.113733.1.9.7':
                                trans_id_value = attr['values'][0]
                                if hasattr(trans_id_value, 'native'):
                                    trans_id = trans_id_value.native
                                else:
                                    trans_id = str(trans_id_value)
                                logger.info(f"Extracted transactionId (SCEP OID): {trans_id}")
                                return trans_id
                            if len(attr['values']) > 0:
                                value = attr['values'][0]
                                logger.debug(f"  Value type: {type(value).__name__}")
                                logger.debug(f"  Value: {value}")
                    else:
                        logger.warning("Signer has no signed_attrs")
                else:
                    logger.warning("No signer_infos found")
            else:
                logger.warning(f"Not signed_data: {content_info['content_type'].native}")
            
            # Default if not found (MD5 of empty string - this is what sscep uses)
            logger.warning("No transactionId found in request, using MD5 of empty string")
            return 'D41D8CD98F00B204E9800998ECF8427E'
            
        except Exception as e:
            logger.error(f"Failed to extract transactionId: {str(e)}", exc_info=True)
            return 'D41D8CD98F00B204E9800998ECF8427E'
    @staticmethod
    def extract_sender_nonce_from_scep(pkcs7_data: bytes) -> Optional[bytes]:
        """Extract senderNonce from SCEP request"""
        try:
            import asn1crypto.cms
            
            content_info = asn1crypto.cms.ContentInfo.load(pkcs7_data)
            
            if content_info['content_type'].native == 'signed_data':
                signed_data = content_info['content']
                signer_infos = signed_data['signer_infos']
                
                if signer_infos and len(signer_infos) > 0:
                    signer = signer_infos[0]
                    
                    if signer['signed_attrs'] is not None:
                        for attr in signer['signed_attrs']:
                            attr_type = attr['type'].native
                            
                            # SenderNonce OID: 2.16.840.1.113733.1.9.5
                            if attr_type == '2.16.840.1.113733.1.9.5':
                                nonce_value = attr['values'][0]
                                # It's an OctetString
                                nonce_bytes = bytes(nonce_value)
                                logger.info(f"Extracted senderNonce: {nonce_bytes.hex()}")
                                return nonce_bytes
            
            logger.warning("No senderNonce found in request")
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract senderNonce: {str(e)}")
            return None

certificate_formatter = CertificateFormatter()