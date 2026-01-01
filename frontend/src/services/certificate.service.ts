import api from './api'
import {
  Certificate,
  CertificateDetail,
  GenerateMachineCertRequest,
  GenerateUserCertRequest,
  RequestServerCertRequest,
  DownloadCertRequest,
  ApproveCertRequest,
  RevokeCertRequest,
  PaginatedResponse,
  CertificateListParams,
} from '@/types';

export const certificateService = {
  /**
   * Get paginated list of certificates
   */
  list: async (params?: CertificateListParams): Promise<PaginatedResponse<Certificate>> => {
    const response = await api.get<PaginatedResponse<Certificate>>('/certificates', { params });
    return response.data;
  },

  /**
   * Get certificate details by ID
   */
  get: async (id: number): Promise<CertificateDetail> => {
    const response = await api.get<CertificateDetail>(`/certificates/${id}`);
    return response.data;
  },

  /**
   * Generate machine certificate (admin only)
   */
  generateMachine: async (data: GenerateMachineCertRequest): Promise<CertificateDetail> => {
    const response = await api.post<CertificateDetail>('/certificates/machine', data);
    return response.data;
  },

  /**
   * Generate user certificate (admin only)
   */
  generateUser: async (data: GenerateUserCertRequest): Promise<CertificateDetail> => {
    const response = await api.post<CertificateDetail>('/certificates/user', data);
    return response.data;
  },

  /**
   * Request server certificate
   */
  requestServer: async (data: RequestServerCertRequest): Promise<CertificateDetail> => {
    const response = await api.post<CertificateDetail>('/certificates/server', data);
    return response.data;
  },

  /**
   * Download certificate
   */
  download: async (id: number, data?: DownloadCertRequest): Promise<Blob> => {
    const response = await api.post(`/certificates/${id}/download`, data, {
      responseType: 'blob',
    });
    return response.data;
  },

  /**
   * Approve or reject certificate (admin only)
   */
  approve: async (id: number, data: ApproveCertRequest): Promise<CertificateDetail> => {
    const response = await api.post<CertificateDetail>(`/certificates/${id}/approve`, data);
    return response.data;
  },

  /**
   * Revoke certificate (admin only)
   */
  revoke: async (id: number, data: RevokeCertRequest): Promise<CertificateDetail> => {
    const response = await api.post<CertificateDetail>(`/certificates/${id}/revoke`, data);
    return response.data;
  },
};