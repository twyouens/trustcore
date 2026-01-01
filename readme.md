# TrustCore - Certificate Authority Management Platform

A modern, API-driven Certificate Authority management platform with a web UI for requesting, signing, and revoking certificates.

## Features

### Certificate Management
- **Machine Certificates**: Generate certificates for EAP-TLS device authentication using MAC addresses
- **User Certificates**: Generate certificates for EAP-TLS user authentication
- **Server Certificates**: Upload CSRs for SSL/TLS certificates with approval workflow
- **Certificate Revocation**: Revoke certificates with CRL (Certificate Revocation List) support
- **OCSP Support**: Online Certificate Status Protocol for real-time certificate validation

### Security & Authentication
- **OIDC Authentication**: Secure authentication with OpenID Connect
- **Just-in-Time (JIT) User Provisioning**: Automatic user creation on first login
- **Role-Based Access Control**: User and Admin roles
- **Audit Logging**: Comprehensive audit trail of all actions

### Workflows
- **Auto-Approval**: Machine and user certificates (admin-generated) are auto-approved
- **Approval Required**: Server certificates require admin approval
- **Certificate Download**: Download certificates in PEM format

## Tech Stack

### Backend
- **FastAPI**: Modern Python web framework
- **SQLAlchemy**: SQL toolkit and ORM
- **PostgreSQL**: Database
- **Cryptography**: Python library for X.509 certificate operations
- **Authlib**: OAuth/OIDC client library

### Deployment
- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration

## Project Structure

```
trustcore/
├── backend/
│   ├── app/
│   │   ├── api/              # API route handlers
│   │   │   ├── auth.py       # Authentication endpoints
│   │   │   ├── certificates.py  # Certificate management
│   │   │   ├── ca.py         # CA information & CRL
│   │   │   └── audit.py      # Audit logs
│   │   ├── core/             # Core configuration
│   │   │   ├── config.py     # Application settings
│   │   │   └── database.py   # Database connection
│   │   ├── models/           # SQLAlchemy models
│   │   │   ├── user.py
│   │   │   ├── certificate.py
│   │   │   └── audit.py
│   │   ├── schemas/          # Pydantic schemas
│   │   │   ├── user.py
│   │   │   ├── certificate.py
│   │   │   ├── ca.py
│   │   │   └── audit.py
│   │   ├── services/         # Business logic
│   │   │   ├── ca_service.py       # CA operations
│   │   │   ├── auth_service.py     # Authentication
│   │   │   ├── certificate_service.py
│   │   │   └── audit_service.py
│   │   └── main.py           # Application entry point
│   ├── alembic/              # Database migrations
│   ├── tests/                # Test files
│   ├── requirements.txt      # Python dependencies
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

## Getting Started

### Prerequisites
- Docker and Docker Compose
- OIDC-compatible Identity Provider (e.g., Keycloak, Auth0, Azure AD)

### Configuration

1. Copy the example environment file:
```bash
cp backend/.env.example backend/.env
```

2. Edit `backend/.env` and configure:

```env
# Database (already configured for Docker)
DATABASE_URL=postgresql://trustcore:trustcore@db:5432/trustcore

# Security - CHANGE THESE IN PRODUCTION!
SECRET_KEY=your-random-secret-key-here

# OIDC Configuration - REQUIRED
OIDC_ISSUER=https://your-idp.example.com
OIDC_CLIENT_ID=trustcore
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=http://localhost:3000/auth/callback

# CA Configuration (customize as needed)
CA_NAME=TrustCore Root CA
CA_COUNTRY=US
CA_STATE=California
CA_LOCALITY=San Francisco
CA_ORGANIZATION=Your Organization
CA_EMAIL=ca@example.com
```

### Running with Docker Compose

1. Start the services:
```bash
docker-compose up -d
```

2. The backend API will be available at: http://localhost:8000
3. API documentation: http://localhost:8000/api/v1/docs

### Initial Setup

The Certificate Authority will be automatically initialized on first startup. The CA certificate and private key will be stored in the `ca_data` volume.

**IMPORTANT**: Back up the `ca_data` volume! It contains the CA private key.

### Database Migrations

Migrations are automatically applied on startup. To create a new migration:

```bash
docker-compose exec backend alembic revision --autogenerate -m "description"
docker-compose exec backend alembic upgrade head
```

## API Documentation

### Authentication Flow

1. **Get Authorization URL**: `GET /api/v1/auth/login`
   - Returns the OIDC authorization URL
   - Frontend redirects user to this URL

2. **Handle Callback**: `POST /api/v1/auth/callback?code={authorization_code}`
   - Exchanges authorization code for JWT token
   - Creates user if doesn't exist (JIT provisioning)
   - Returns JWT access token

3. **Get Current User**: `GET /api/v1/auth/me`
   - Requires: `Authorization: Bearer {token}`
   - Returns current user information

### Certificate Endpoints

#### Machine Certificates (Admin Only)
```http
POST /api/v1/certificates/machine
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "validity_days": 365
}
```

#### User Certificates (Admin Only)
```http
POST /api/v1/certificates/user
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "username": "john.doe",
  "validity_days": 365
}
```

#### Server Certificates (Any Authenticated User)
```http
POST /api/v1/certificates/server
Authorization: Bearer {token}
Content-Type: application/json

{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "validity_days": 365
}
```

#### List Certificates
```http
GET /api/v1/certificates?status=approved&certificate_type=server
Authorization: Bearer {token}
```

#### Download Certificate
```http
GET /api/v1/certificates/{id}/download
Authorization: Bearer {token}
```

#### Approve Certificate (Admin Only)
```http
POST /api/v1/certificates/{id}/approve
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "approved": true
}
```

#### Revoke Certificate (Admin Only)
```http
POST /api/v1/certificates/{id}/revoke
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "reason": "Key compromise"
}
```

### CA Endpoints (Public)

#### Get CA Certificate
```http
GET /api/v1/ca/certificate
```

#### Get CA Information
```http
GET /api/v1/ca/info
```

#### Get CRL (Certificate Revocation List)
```http
GET /api/v1/ca/crl
```

### Audit Logs (Admin Only)

```http
GET /api/v1/audit?action=certificate_approved&skip=0&limit=100
Authorization: Bearer {admin_token}
```

## Use Cases

### 1. EAP-TLS WiFi Authentication - Machine Certificates

**Scenario**: Deploy certificates to network devices for 802.1X authentication

```bash
# Admin generates certificate for a device
curl -X POST http://localhost:8000/api/v1/certificates/machine \
  -H "Authorization: Bearer {admin_token}" \
  -H "Content-Type: application/json" \
  -d '{
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "validity_days": 730
  }'

# Response includes both private key and certificate
# Deploy to device's supplicant configuration
```

### 2. EAP-TLS WiFi Authentication - User Certificates

**Scenario**: Issue certificates to users for wireless authentication

```bash
# Admin generates certificate for a user
curl -X POST http://localhost:8000/api/v1/certificates/user \
  -H "Authorization: Bearer {admin_token}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "validity_days": 365
  }'

# User downloads and installs certificate on their device
```

### 3. Internal Website SSL/TLS Certificates

**Scenario**: User needs a certificate for an internal web server

```bash
# 1. User generates CSR on their server
openssl req -new -newkey rsa:2048 -nodes \
  -keyout server.key \
  -out server.csr \
  -subj "/CN=internal.example.com" \
  -addext "subjectAltName=DNS:internal.example.com,DNS:www.internal.example.com"

# 2. User submits CSR via API
curl -X POST http://localhost:8000/api/v1/certificates/server \
  -H "Authorization: Bearer {user_token}" \
  -H "Content-Type: application/json" \
  -d "{
    \"csr\": \"$(cat server.csr | sed ':a;N;$!ba;s/\n/\\n/g')\",
    \"validity_days\": 365
  }"

# 3. Admin reviews and approves
curl -X POST http://localhost:8000/api/v1/certificates/123/approve \
  -H "Authorization: Bearer {admin_token}" \
  -H "Content-Type: application/json" \
  -d '{"approved": true}'

# 4. User downloads certificate
curl http://localhost:8000/api/v1/certificates/123/download \
  -H "Authorization: Bearer {user_token}" \
  -o server.crt
```

## Security Considerations

### Production Deployment

1. **Change Secret Keys**: Generate strong random secrets for `SECRET_KEY`
2. **Secure CA Private Key**: 
   - Store `ca_data` volume on encrypted storage
   - Implement backup strategy
   - Consider HSM for production environments
3. **HTTPS Only**: Deploy behind reverse proxy with TLS
4. **Database Security**: Use strong passwords, enable SSL connections
5. **Network Isolation**: Restrict database access to backend only
6. **Audit Logs**: Regularly review audit logs for suspicious activity

### CA Key Protection

The CA private key is the most critical asset. In production:
- Store in Hardware Security Module (HSM)
- Implement key ceremony procedures
- Use offline root CA with online intermediate CA
- Regular backups with encryption

## Monitoring & Maintenance

### Health Check
```http
GET /health
```

### Certificate Expiration Monitoring

Query certificates expiring soon:
```sql
SELECT * FROM certificates 
WHERE status = 'approved' 
AND not_after < NOW() + INTERVAL '30 days';
```

### CRL Updates

The CRL is automatically updated when:
- Certificates are revoked
- CRL endpoint is accessed

Configure automatic CRL updates in your systems.

## Troubleshooting

### CA Not Initialized
```bash
# Check CA files exist
docker-compose exec backend ls -la /app/ca_data

# Manually trigger initialization
docker-compose exec backend python -c "from app.services.ca_service import ca_service; ca_service.initialize_ca()"
```

### Database Connection Issues
```bash
# Check database is running
docker-compose ps db

# Check database logs
docker-compose logs db

# Test connection
docker-compose exec backend python -c "from app.core.database import engine; engine.connect()"
```

### OIDC Authentication Issues
- Verify OIDC configuration in `.env`
- Check OIDC provider logs
- Ensure redirect URI is registered with OIDC provider
- Check network connectivity to OIDC provider

## Development

### Running Tests
```bash
docker-compose exec backend pytest
```

### Adding New Features

1. Create database model in `app/models/`
2. Create Pydantic schemas in `app/schemas/`
3. Implement business logic in `app/services/`
4. Create API routes in `app/api/`
5. Generate migration: `alembic revision --autogenerate`
6. Apply migration: `alembic upgrade head`

## API Client Examples

### Python
```python
import requests

# Login and get token
response = requests.post(
    "http://localhost:8000/api/v1/auth/callback",
    params={"code": "authorization_code"}
)
token = response.json()["access_token"]

# Request certificate
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(
    "http://localhost:8000/api/v1/certificates/machine",
    headers=headers,
    json={"mac_address": "AA:BB:CC:DD:EE:FF", "validity_days": 365}
)
certificate = response.json()
```

### JavaScript/TypeScript
```javascript
// Login and get token
const authResponse = await fetch(
  `http://localhost:8000/api/v1/auth/callback?code=${code}`,
  { method: 'POST' }
);
const { access_token } = await authResponse.json();

// Request certificate
const response = await fetch(
  'http://localhost:8000/api/v1/certificates/machine',
  {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${access_token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      mac_address: 'AA:BB:CC:DD:EE:FF',
      validity_days: 365
    })
  }
);
const certificate = await response.json();
```

## License

[Add your license here]

## Support

[Add support information here]

## Contributing

[Add contributing guidelines here]