import api from './api';
import {
  APIToken,
  APITokenWithToken,
  CreateAPITokenRequest,
  UpdateAPITokenRequest,
} from '@/types';

export const apiTokenService = {
  /**
   * Create a new API token (admin only)
   */
  create: async (data: CreateAPITokenRequest): Promise<APITokenWithToken> => {
    const response = await api.post<APITokenWithToken>('/tokens', data);
    return response.data;
  },

  /**
   * List all API tokens
   */
  list: async (includeInactive?: boolean): Promise<APIToken[]> => {
    const response = await api.get<APIToken[]>('/tokens', {
      params: { include_inactive: includeInactive },
    });
    return response.data;
  },

  /**
   * Get specific API token
   */
  get: async (id: number): Promise<APIToken> => {
    const response = await api.get<APIToken>(`/tokens/${id}`);
    return response.data;
  },

  /**
   * Update API token
   */
  update: async (id: number, data: UpdateAPITokenRequest): Promise<APIToken> => {
    const response = await api.patch<APIToken>(`/tokens/${id}`, data);
    return response.data;
  },

  /**
   * Revoke API token (soft delete)
   */
  revoke: async (id: number): Promise<void> => {
    await api.delete(`/tokens/${id}`);
  },

};