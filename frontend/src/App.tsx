import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ConfigProvider } from 'antd';
import { AppLayout } from './components/AppLayout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { AuthCallback } from './pages/AuthCallback';
import { Dashboard } from './pages/Dashboard';
import { CertificateList } from './pages/CertificateList';
import { CertificateDetail } from './pages/CertificateDetail';
import { RequestServerCert } from './pages/RequestServerCert';
import { GenerateMachineCert } from './pages/GenerateMachineCert';
import { GenerateUserCert } from './pages/GenerateUserCert';
import { PendingApprovals } from './pages/PendingApprovals';
import { AuditLogs } from './pages/AuditLogs';
import { CAInformation } from './pages/CAInformation';
import { UserProfile } from './pages/UserProfile';
import { APITokens } from './pages/APITokens';
import { APITokenDetail } from './pages/APITokenDetail';
import { SCEPClients } from './pages/SCEPClients';
import { SCEPClientDetail } from './pages/SCEPClientDetail';
import './App.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

function App() {
  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#14ba08ff',
          borderRadius: 8,
          fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        },
      }}
    >
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/auth/callback" element={<AuthCallback />} />
            
            <Route element={<ProtectedRoute />}>
              <Route element={<AppLayout />}>
                <Route path="/" element={<Dashboard />} />
                <Route path="/certificates" element={<CertificateList />} />
                <Route path="/certificates/:id" element={<CertificateDetail />} />
                <Route path="/certificates/request-server" element={<RequestServerCert />} />
                <Route path="/ca-info" element={<CAInformation />} />
                <Route path="/profile" element={<UserProfile />} />
              </Route>
            </Route>

            <Route element={<ProtectedRoute requireAdmin />}>
              <Route element={<AppLayout />}>
                <Route path="/certificates/generate-machine" element={<GenerateMachineCert />} />
                <Route path="/certificates/generate-user" element={<GenerateUserCert />} />
                <Route path="/approvals" element={<PendingApprovals />} />
                <Route path="/settings/audit" element={<AuditLogs />} />
                <Route path="/settings/api-tokens" element={<APITokens />} />
                <Route path="/settings/api-tokens/:id" element={<APITokenDetail />} />
                <Route path="/settings/scep-clients" element={<SCEPClients />} />
                <Route path="/settings/scep-clients/:id" element={<SCEPClientDetail />} />
              </Route>
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </QueryClientProvider>
    </ConfigProvider>
  );
}

export default App;