SCEP_CLIENT_ID="8bc53952-7cf9-4623-872f-1b30facf1e60"
SCEP_URL="http://localhost:8000/api/v1/scep/$SCEP_CLIENT_ID/pkiclient.exe"

# Send CSR (accepts both PKCS#7 wrapped and plain PEM)
curl -X POST "${SCEP_URL}?operation=PKIOperation" \
  --data-binary @device.csr \
  -o response.p7b

# Check if response is PKCS#7
file response.p7b

# Extract certificate from PKCS#7 response
openssl pkcs7 -print_certs -in response.p7b -inform DER -out device.pem

# View issued certificate
openssl x509 -in device.pem -text -noout

# Verify certificate chain
openssl verify -CAfile ca.pem device.pem