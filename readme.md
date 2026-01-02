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
