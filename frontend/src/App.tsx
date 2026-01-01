import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ConfigProvider } from 'antd';
import { AppLayout } from './components/AppLayout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { AuthCallback } from './pages/AuthCallback';
import { Dashboard } from './pages/Dashboard';
// Import other pages (will be created)
// import { CertificateList } from './pages/CertificateList';
// import { CertificateDetail } from './pages/CertificateDetail';
// import { RequestServerCert } from './pages/RequestServerCert';
// import { GenerateMachineCert } from './pages/GenerateMachineCert';
// import { GenerateUserCert } from './pages/GenerateUserCert';
// import { PendingApprovals } from './pages/PendingApprovals';
// import { AuditLogs } from './pages/AuditLogs';
// import { CAInformation } from './pages/CAInformation';
// import { UserProfile } from './pages/UserProfile';
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
          colorPrimary: '#1890ff',
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
                <Route path="/certificates" element={<div>Certificate List (Coming Soon)</div>} />
                <Route path="/certificates/:id" element={<div>Certificate Detail (Coming Soon)</div>} />
                <Route path="/certificates/request-server" element={<div>Request Server Cert (Coming Soon)</div>} />
                <Route path="/ca-info" element={<div>CA Information (Coming Soon)</div>} />
                <Route path="/profile" element={<div>Profile (Coming Soon)</div>} />
              </Route>
            </Route>

            <Route element={<ProtectedRoute requireAdmin />}>
              <Route element={<AppLayout />}>
                <Route path="/certificates/generate-machine" element={<div>Generate Machine Cert (Coming Soon)</div>} />
                <Route path="/certificates/generate-user" element={<div>Generate User Cert (Coming Soon)</div>} />
                <Route path="/approvals" element={<div>Pending Approvals (Coming Soon)</div>} />
                <Route path="/audit" element={<div>Audit Logs (Coming Soon)</div>} />
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