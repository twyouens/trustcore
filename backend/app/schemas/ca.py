from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class CAInfoResponse(BaseModel):
    ca_certificate: str  # PEM encoded CA certificate
    ca_name: str
    not_before: datetime
    not_after: datetime
    serial_number: str
    issuer: str
    subject: str


class CRLResponse(BaseModel):
    crl: str  # PEM encoded CRL
    last_update: datetime
    next_update: datetime