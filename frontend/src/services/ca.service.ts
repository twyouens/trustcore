import api from './api';
import { CAInfo } from '@/types';

export const caService = {
  /**
   * Get CA certificate (PEM format)
   */
  getCertificate: async (): Promise<string> => {
    const response = await api.get<string>('/ca/certificate', {
      responseType: 'text',
    });
    return response.data;
  },

  /**
   * Get CA information
   */
  getInfo: async (): Promise<CAInfo> => {
    const response = await api.get<CAInfo>('/ca/info');
    return response.data;
  },

  /**
   * Get Certificate Revocation List (CRL)
   */
  getCRL: async (): Promise<string> => {
    const response = await api.get<string>('/ca/crl', {
      responseType: 'text',
    });
    return response.data;
  },
};