import { Navigate, Outlet } from 'react-router-dom';
import { useAuthStore } from '@/store/authStore';
import { Spin } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { authService } from '@/services/auth.service';

interface ProtectedRouteProps {
  requireAdmin?: boolean;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ requireAdmin = false }) => {
  const { isAuthenticated, user, setUser } = useAuthStore();

  const { isLoading } = useQuery({
    queryKey: ['currentUser'],
    queryFn: async () => {
      const userData = await authService.getCurrentUser();
      setUser(userData);
      return userData;
    },
    enabled: isAuthenticated && !user,
    retry: false,
  });

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" tip="Loading..." />
      </div>
    );
  }

  if (requireAdmin && user?.role !== 'admin') {
    return (
      <div style={{ padding: '50px', textAlign: 'center' }}>
        <h1>403 - Forbidden</h1>
        <p>You do not have permission to access this page.</p>
      </div>
    );
  }

  return <Outlet />;
};