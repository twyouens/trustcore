SCEP_CLIENT_ID="8bc53952-7cf9-4623-872f-1b30facf1e60"
SCEP_URL="http://localhost:8000/api/v1/scep/$SCEP_CLIENT_ID/pkiclient.exe"

# Get CA certificate (now returns PKCS#7)
curl "${SCEP_URL}?operation=GetCACert" -o ca.p7b

# Extract certificate from PKCS#7
openssl pkcs7 -print_certs -in ca.p7b -inform DER -out ca.pem

# View certificate
openssl x509 -in ca.pem -text -noout