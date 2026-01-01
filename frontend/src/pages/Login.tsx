import { useState } from 'react';
import { Button, Card, Typography, Space, message } from 'antd';
import { SafetyCertificateOutlined, LoginOutlined } from '@ant-design/icons';
import { authService } from '@/services/auth.service';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '@/store/authStore';
import './Login.css';

const { Title } = Typography;

export const Login = () => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { isAuthenticated } = useAuthStore();

  // Redirect if already authenticated
  if (isAuthenticated) {
    navigate('/', { replace: true });
    return null;
  }

  const handleLogin = async () => {
    try {
      setLoading(true);
      const authUrl = await authService.getAuthorizationUrl();
      console.log('Redirecting to auth URL:', authUrl);
      if (!authUrl) {
        message.error('Failed to get authorization URL. Please try again.');
        setLoading(false);
        return;
      }
      window.location.href = authUrl;
    } catch (error) {
      message.error('Failed to initiate login. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-background">
        <div className="cert-pattern"></div>
      </div>
      <Card className="login-card">
        <Space direction="vertical" size="large" style={{ width: '100%', textAlign: 'center' }}>
          <div className="login-logo">
            <SafetyCertificateOutlined className="login-icon" />
            <Title level={2} className="login-title">
              TrustCore
            </Title>
          </div>
          
          <div>
            <Title level={4} style={{ marginBottom: 8 }}>
              Certificate Management
            </Title>
          </div>

          <Button
            type="primary"
            size="large"
            icon={<LoginOutlined />}
            onClick={handleLogin}
            loading={loading}
            block
            className="login-button"
          >
            Login with OIDC
          </Button>
        </Space>
      </Card>
    </div>
  );
};