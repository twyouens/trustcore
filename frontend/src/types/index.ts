// User types
export interface User {
  id: number;
  email: string;
  username: string;
  full_name: string | null;
  role: 'user' | 'admin';
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

// Certificate types
export type CertificateType = 'machine' | 'user' | 'server';
export type CertificateStatus = 'pending' | 'approved' | 'rejected' | 'revoked';
export type OutputFormat = 'pem' | 'pkcs12' | 'der';

export interface Certificate {
  id: number;
  serial_number: string;
  certificate_type: CertificateType;
  common_name: string;
  subject_alternative_names: string[] | null;
  status: CertificateStatus;
  validity_days: number;
  not_before: string | null;
  not_after: string | null;
  created_at: string;
  approved_at: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
  requested_by_id: number;
  approved_by_id: number | null;
  revoked_by_id: number | null;
  auto_approved: boolean;
}

export interface CertificateDetail extends Certificate {
  certificate: string | null;
  csr: string | null;
}

// API Request types
export interface GenerateMachineCertRequest {
  mac_address: string;
  validity_days: number;
  output_format?: OutputFormat;
  pkcs12_password?: string;
}

export interface GenerateUserCertRequest {
  username?: string;
  validity_days: number;
  output_format?: OutputFormat;
  pkcs12_password?: string;
}

export interface RequestServerCertRequest {
  csr: string;
  validity_days: number;
  output_format?: OutputFormat;
  pkcs12_password?: string;
}

export interface DownloadCertRequest {
  output_format?: OutputFormat;
  pkcs12_password?: string;
}

export interface ApproveCertRequest {
  approved: boolean;
  rejection_reason?: string;
}

export interface RevokeCertRequest {
  reason: string;
}

// API Response types
export interface PaginatedResponse<T> {
  total: number;
  items: T[];
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
}

export interface AuthUrlResponse {
  redirect_uri: string;
}

// Audit Log types
export interface AuditLog {
  id: number;
  action: string;
  resource_type: string;
  resource_id: number | null;
  user_id: number | null;
  details: Record<string, any> | null;
  ip_address: string | null;
  created_at: string;
}

// CA Info types
export interface CAInfo {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  signature_algorithm: string;
  key_size: number;
}

// Query params types
export interface CertificateListParams {
  status?: CertificateStatus;
  certificate_type?: CertificateType;
  skip?: number;
  limit?: number;
}

export interface AuditLogParams {
  action?: string;
  resource_type?: string;
  user_id?: number;
  skip?: number;
  limit?: number;
}