import { Card, Descriptions, Space, Typography, Tag } from 'antd';
import { UserOutlined } from '@ant-design/icons';
import { useAuthStore } from '@/store/authStore';
import { formatDate } from '@/utils/helpers';

const { Title, Text } = Typography;

export const UserProfile = () => {
  const { user } = useAuthStore();

  if (!user) {
    return <Card loading />;
  }

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>User Profile</Title>
        <Text type="secondary">Your account information and settings</Text>
      </div>

      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
            <div
              style={{
                width: 80,
                height: 80,
                borderRadius: '50%',
                background: 'linear-gradient(135deg, #667eea 0%, #55a24b 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'white',
                fontSize: 32,
              }}
            >
              <UserOutlined />
            </div>
            <div>
              <Title level={3} style={{ marginBottom: 4 }}>
                {user.full_name || user.username}
              </Title>
              <Space>
                <Tag color={user.role === 'admin' ? 'red' : 'blue'}>
                  {user.role}
                </Tag>
                <Tag color={user.is_active ? 'green' : 'default'}>
                  {user.is_active ? 'Active' : 'Inactive'}
                </Tag>
              </Space>
            </div>
          </div>

          <Descriptions bordered column={2}>
            <Descriptions.Item label="Username" span={2}>
              {user.username}
            </Descriptions.Item>
            <Descriptions.Item label="Email" span={2}>
              {user.email}
            </Descriptions.Item>
            <Descriptions.Item label="Full Name" span={2}>
              {user.full_name || 'Not set'}
            </Descriptions.Item>
            <Descriptions.Item label="User ID" span={2}>
              {user.id}
            </Descriptions.Item>
            <Descriptions.Item label="Role" span={2}>
              <Tag color={user.role === 'admin' ? 'red' : 'blue'}>
                {user.role}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Account Status" span={2}>
              <Tag color={user.is_active ? 'green' : 'default'}>
                {user.is_active ? 'Active' : 'Inactive'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Last Login" span={2}>
              {user.last_login ? formatDate(user.last_login) : 'Never'}
            </Descriptions.Item>
          </Descriptions>
        </Card>
      </Space>
    </div>
  );
};