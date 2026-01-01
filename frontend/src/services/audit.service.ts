import api from './api';
import { AuditLog, PaginatedResponse, AuditLogParams } from '@/types';

export const auditService = {
  /**
   * Get paginated list of audit logs (admin only)
   */
  list: async (params?: AuditLogParams): Promise<PaginatedResponse<AuditLog>> => {
    const response = await api.get<PaginatedResponse<AuditLog>>('/audit', { params });
    return response.data;
  },
};