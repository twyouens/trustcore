from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://trustcore:trustcore@localhost:5432/trustcore"
    
    # Redis (optional - for OAuth state storage)
    REDIS_URL: Optional[str] = None
    
    # Security
    SECRET_KEY: str = "change-this-to-a-random-secret-key-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # OIDC Configuration
    OIDC_ISSUER: str
    OIDC_CLIENT_ID: str
    OIDC_CLIENT_SECRET: str
    OIDC_REDIRECT_URI: str = "http://localhost:3000/auth/callback"
    OIDC_USER_KEY: str = "sub"
    OIDC_ADMIN_GROUP: str = "admins"
    OIDC_SCOPE: str = "openid profile email"

    # CA Configuration
    CA_NAME: str = "TrustCore Root CA"
    CA_COUNTRY: str = "US"
    CA_STATE: str = "California"
    CA_LOCALITY: str = "San Francisco"
    CA_ORGANIZATION: str = "Your Organization"
    CA_ORGANIZATIONAL_UNIT: str = "IT Department"
    CA_EMAIL: Optional[str] = None
    CA_VALIDITY_DAYS: int = 7300  # 20 years for root CA
    CA_KEY_SIZE: int = 4096
    
    # Certificate Defaults
    DEFAULT_CERT_VALIDITY_DAYS: int = 365
    MAX_CERT_VALIDITY_DAYS: int = 3650  # 10 years
    DEFAULT_KEY_SIZE: int = 2048
    
    # CRL & OCSP
    CRL_ENABLED: bool = True
    CRL_UPDATE_HOURS: int = 24
    OCSP_ENABLED: bool = True
    OCSP_URL: str = "http://localhost:8000/ocsp"
    
    # Application
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "TrustCore"
    
    # Storage paths
    CA_STORAGE_PATH: str = "/app/ca_data"
    CA_KEY_FILE: str = "ca_key.pem"
    CA_CERT_FILE: str = "ca_cert.pem"
    CRL_FILE: str = "crl.pem"

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "app.log"
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()