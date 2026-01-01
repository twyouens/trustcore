import { CertificateStatus, CertificateType, OutputFormat } from '@/types';
import dayjs from 'dayjs';

/**
 * Format MAC address as user types
 */
export const formatMacAddress = (value: string): string => {
  const cleaned = value.replace(/[^0-9A-Fa-f]/g, '');
  const parts = cleaned.match(/.{1,2}/g) || [];
  return parts.join(':').toUpperCase().slice(0, 17);
};

/**
 * Validate MAC address format
 */
export const validateMacAddress = (mac: string): boolean => {
  const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
  return macRegex.test(mac);
};

/**
 * Get color for certificate status badge
 */
export const getStatusColor = (status: CertificateStatus): string => {
  const colors: Record<CertificateStatus, string> = {
    pending: 'warning',
    approved: 'success',
    rejected: 'error',
    revoked: 'default',
  };
  return colors[status] || 'default';
};

/**
 * Get color for certificate type badge
 */
export const getTypeColor = (type: CertificateType): string => {
  const colors: Record<CertificateType, string> = {
    machine: 'blue',
    user: 'purple',
    server: 'cyan',
  };
  return colors[type] || 'default';
};

/**
 * Format date to human-readable string
 */
export const formatDate = (date: string | null): string => {
  if (!date) return 'N/A';
  return dayjs(date).format('MMM DD, YYYY HH:mm');
};

/**
 * Format date for display (short version)
 */
export const formatDateShort = (date: string | null): string => {
  if (!date) return 'N/A';
  return dayjs(date).format('MMM DD, YYYY');
};

/**
 * Calculate days until expiry
 */
export const getDaysUntilExpiry = (expiryDate: string): number => {
  return dayjs(expiryDate).diff(dayjs(), 'day');
};

/**
 * Check if certificate is expiring soon (within 30 days)
 */
export const isExpiringSoon = (expiryDate: string | null): boolean => {
  if (!expiryDate) return false;
  const daysUntilExpiry = getDaysUntilExpiry(expiryDate);
  return daysUntilExpiry >= 0 && daysUntilExpiry <= 30;
};

/**
 * Check if certificate is expired
 */
export const isExpired = (expiryDate: string | null): boolean => {
  if (!expiryDate) return false;
  return getDaysUntilExpiry(expiryDate) < 0;
};

/**
 * Get file extension for output format
 */
export const getFileExtension = (format: OutputFormat): string => {
  const extensions: Record<OutputFormat, string> = {
    pem: 'pem',
    pkcs12: 'p12',
    der: 'der',
  };
  return extensions[format] || 'pem';
};

/**
 * Download file from blob
 */
export const downloadBlob = (blob: Blob, filename: string): void => {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
};

/**
 * Download text as file
 */
export const downloadText = (text: string, filename: string): void => {
  const blob = new Blob([text], { type: 'text/plain' });
  downloadBlob(blob, filename);
};

/**
 * Parse CSR to extract information
 * Note: This is a simplified version. In production, you'd use a proper library like node-forge
 */
export const parseCSR = (csrPem: string): { cn: string; sans: string[] } | null => {
  try {
    // This is a placeholder. In a real application, you'd use a library to parse the CSR
    // For now, we'll return mock data or make an API call to validate
    const lines = csrPem.split('\n');
    const hasBegin = lines.some(line => line.includes('BEGIN CERTIFICATE REQUEST'));
    const hasEnd = lines.some(line => line.includes('END CERTIFICATE REQUEST'));
    
    if (!hasBegin || !hasEnd) {
      return null;
    }
    
    // In production, use node-forge or make an API call to parse
    return {
      cn: 'example.com',
      sans: ['www.example.com', 'api.example.com'],
    };
  } catch (error) {
    return null;
  }
};

/**
 * Validate CSR format
 */
export const validateCSR = (csr: string): boolean => {
  if (!csr || typeof csr !== 'string') return false;
  const trimmed = csr.trim();
  return (
    trimmed.includes('BEGIN CERTIFICATE REQUEST') &&
    trimmed.includes('END CERTIFICATE REQUEST')
  );
};

/**
 * Copy text to clipboard
 */
export const copyToClipboard = async (text: string): Promise<boolean> => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Failed to copy to clipboard:', error);
    return false;
  }
};

/**
 * Get default PKCS12 password based on certificate type and identifier
 */
export const getDefaultPassword = (type: CertificateType, identifier: string): string => {
  if (type === 'machine') {
    return identifier; // MAC address
  }
  return identifier; // Username for user certs
};