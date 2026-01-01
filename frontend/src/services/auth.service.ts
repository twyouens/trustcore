import api from './api';
import { User, AuthResponse, AuthUrlResponse } from '@/types';

export const authService = {
  /**
   * Get the OIDC authorization URL
   */
  getAuthorizationUrl: async (): Promise<string> => {
    const response = await api.get<AuthUrlResponse>('/auth/login');
    return response.data.redirect_uri;
  },

  /**
   * Exchange authorization code for access token
   */
  exchangeCode: async (code: string, state: string): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>(
      `/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`
    );
    return response.data;
  },

  /**
   * Get current user information
   */
  getCurrentUser: async (): Promise<User> => {
    const response = await api.get<User>('/auth/me');
    return response.data;
  },

  /**
   * Logout (clear local token)
   */
  logout: () => {
    localStorage.removeItem('trustcore_token');
  },
};