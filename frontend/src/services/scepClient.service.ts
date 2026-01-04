import api from './api';
import {
  SCEPClient,
  CreateSCEPClientRequest,
  UpdateSCEPClientRequest,
  SCEPClientStats,
} from '@/types';

export const scepClientService = {
  /**
   * Create a new SCEP client (admin only)
   */
  create: async (data: CreateSCEPClientRequest): Promise<SCEPClient> => {
    const response = await api.post<SCEPClient>('/scep/clients', data);
    return response.data;
  },

  /**
   * List all SCEP clients
   */
  list: async (includeDisabled?: boolean): Promise<SCEPClient[]> => {
    const response = await api.get<SCEPClient[]>('/scep/clients', {
      params: { include_disabled: includeDisabled },
    });
    return response.data;
  },

  /**
   * Get SCEP client statistics
   */
  getStats: async (): Promise<SCEPClientStats[]> => {
    const response = await api.get<SCEPClientStats[]>('/scep/clients/stats');
    return response.data;
  },

  /**
   * Get specific SCEP client
   */
  get: async (id: string): Promise<SCEPClient> => {
    const response = await api.get<SCEPClient>(`/scep/clients/${id}`);
    return response.data;
  },

  /**
   * Update SCEP client
   */
  update: async (id: string, data: UpdateSCEPClientRequest): Promise<SCEPClient> => {
    const response = await api.patch<SCEPClient>(`/scep/clients/${id}`, data);
    return response.data;
  },

  /**
   * Delete SCEP client
   */
  delete: async (id: string): Promise<void> => {
    await api.delete(`/scep/clients/${id}`);
  },

  /**
   * Enable SCEP client
   */
  enable: async (id: string): Promise<SCEPClient> => {
    const response = await api.post<SCEPClient>(`/scep/clients/${id}/enable`);
    return response.data;
  },

  /**
   * Disable SCEP client
   */
  disable: async (id: string): Promise<SCEPClient> => {
    const response = await api.post<SCEPClient>(`/scep/clients/${id}/disable`);
    return response.data;
  },
};