import { getApiBaseUrl } from '@/services/api';

/**
 * Get the full API base URL
 */
export const getFullApiUrl = (): string => {
  return getApiBaseUrl();
};

/**
 * Get the CA certificate URL
 */
export const getCaCertificateUrl = (): string => {
  return `${getApiBaseUrl()}/ca/certificate`;
};

/**
 * Get the CRL URL
 */
export const getCrlUrl = (): string => {
  return `${getApiBaseUrl()}/ca/crl`;
};

/**
 * Get the CA info URL
 */
export const getCaInfoUrl = (): string => {
  return `${getApiBaseUrl()}/ca/info`;
};

/**
 * Get the OCSP responder URL
 */
export const getOcspUrl = (): string => {
  return `${getApiBaseUrl()}/ca/ocsp`;
};
