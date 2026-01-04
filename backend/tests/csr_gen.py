import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.backends import default_backend

def create_pkcs7_csr(common_name, output_file):
    # Generate key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Arzyne"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name),
        ])
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Save private key
    with open("device.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save CSR as PEM (for PKCS#7 wrapping)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    with open(output_file, "wb") as f:
        f.write(csr_pem)
    
    print(f"Created CSR: {output_file}")
    print(f"Private key: device.key")
    return csr_pem

if __name__ == "__main__":
    cn = sys.argv[1] if len(sys.argv) > 1 else "AA:BB:CC:DD:EE:FF"
    create_pkcs7_csr(cn, "device.csr")