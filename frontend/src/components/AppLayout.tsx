import { Layout, Menu, Avatar, Dropdown, Badge, Typography } from 'antd';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '@/store/authStore';
import { authService } from '@/services/auth.service';
import {
  DashboardOutlined,
  SafetyCertificateOutlined,
  FileAddOutlined,
  CheckSquareOutlined,
  AuditOutlined,
  InfoCircleOutlined,
  UserOutlined,
  LogoutOutlined,
  LaptopOutlined,
  TeamOutlined,
  CloudServerOutlined,
  SettingOutlined,
  ApiOutlined,
  CreditCardOutlined
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { certificateService } from '@/services/certificate.service';
import './AppLayout.css';

const { Header, Content, Sider } = Layout;
const { Title } = Typography;

export const AppLayout = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuthStore();
  const isAdmin = user?.role === 'admin';

  // Fetch pending approvals count for admin
  const { data: pendingCount } = useQuery({
    queryKey: ['pendingCount'],
    queryFn: async () => {
      const result = await certificateService.list({ status: 'pending', limit: 1 });
      return result.total;
    },
    enabled: isAdmin,
    refetchInterval: 30000, // Refetch every 30 seconds
  });

  const handleLogout = () => {
    authService.logout();
    logout();
    navigate('/login');
  };

  const userMenuItems = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: 'Profile',
      onClick: () => navigate('/profile'),
    },
    {
      type: 'divider' as const,
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: 'Logout',
      onClick: handleLogout,
    },
  ];

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: 'Dashboard',
      onClick: () => navigate('/'),
    },
    {
      key: '/certificates',
      icon: <SafetyCertificateOutlined />,
      label: 'Certificates',
      onClick: () => navigate('/certificates'),
    },
    {
      key: 'request',
      icon: <FileAddOutlined />,
      label: 'Request Certificate',
      children: [
        {
          key: '/certificates/request-server',
          icon: <CloudServerOutlined />,
          label: 'Server Certificate',
          onClick: () => navigate('/certificates/request-server'),
        },
        ...(isAdmin
          ? [
              {
                key: '/certificates/generate-machine',
                icon: <LaptopOutlined />,
                label: 'Machine Certificate',
                onClick: () => navigate('/certificates/generate-machine'),
              },
              {
                key: '/certificates/generate-user',
                icon: <TeamOutlined />,
                label: 'User Certificate',
                onClick: () => navigate('/certificates/generate-user'),
              },
            ]
          : []),
      ],
    },
    ...(isAdmin
      ? [
          {
            key: '/approvals',
            icon: <CheckSquareOutlined />,
            label: (
              <span>
                Pending Approvals
                {pendingCount && pendingCount > 0 ? (
                  <Badge count={pendingCount} style={{ marginLeft: 8 }} />
                ) : null}
              </span>
            ),
            onClick: () => navigate('/approvals'),
          },
        ]
      : []),
    {
      key: '/ca-info',
      icon: <InfoCircleOutlined />,
      label: 'CA Information',
      onClick: () => navigate('/ca-info'),
    },
    ...(isAdmin
      ? [
          {
            key: 'settings',
            icon: <SettingOutlined />,
            label: 'Settings',
            children: [
              {
                key: '/settings/api-tokens',
                icon: <CreditCardOutlined />,
                label: 'API Tokens',
                onClick: () => navigate('/settings/api-tokens'),
              },
              {
                key: '/settings/scep-clients',
                icon: <ApiOutlined />,
                label: 'SCEP Clients',
                onClick: () => navigate('/settings/scep-clients'),
              },
              {
                key: '/settings/audit',
                icon: <AuditOutlined />,
                label: 'Audit Logs',
                onClick: () => navigate('/settings/audit'),
              },
            ],
          },
        ]
      : []),
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider width={250} theme="light" className="app-sider">
        <div className="logo-container">
          <SafetyCertificateOutlined className="logo-icon" />
          <Title level={3} className="logo-text">
            TrustCore
          </Title>
        </div>
        <Menu
          mode="inline"
          selectedKeys={[location.pathname]}
          defaultOpenKeys={['request', 'settings']}
          items={menuItems}
          style={{ borderRight: 0 }}
        />
      </Sider>
      <Layout>
        <Header className="app-header">
          <div className="header-content">
            <div className="header-title">Certificate Management</div>
            <Dropdown menu={{ items: userMenuItems }} placement="bottomRight">
              <div className="user-menu">
                <Avatar icon={<UserOutlined />} style={{ backgroundColor: '#177312ff' }} />
                <span className="user-info">
                  <span className="user-name">{user?.full_name || user?.username}</span>
                  <span className="user-username">{user?.username}</span>
                </span>
              </div>
            </Dropdown>
          </div>
        </Header>
        <Content className="app-content">
          <div className="content-wrapper">
            <Outlet />
          </div>
        </Content>
      </Layout>
    </Layout>
  );
};