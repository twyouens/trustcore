import { Card, Row, Col, Statistic, Button, Table, Typography, Space, Tag } from 'antd';
import {
  SafetyCertificateOutlined,
  ClockCircleOutlined,
  CheckCircleOutlined,
  FileAddOutlined,
  LaptopOutlined,
  TeamOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { certificateService } from '@/services/certificate.service';
import { useAuthStore } from '@/store/authStore';
import { useNavigate } from 'react-router-dom';
import { CertificateStatusBadge } from '@/components/CertificateStatusBadge';
import { CertificateTypeBadge } from '@/components/CertificateTypeBadge';
import { formatDate } from '@/utils/helpers';
import { Certificate } from '@/types';
import type { ColumnsType } from 'antd/es/table';

const { Title } = Typography;

export const Dashboard = () => {
  const navigate = useNavigate();
  const { user } = useAuthStore();
  const isAdmin = user?.role === 'admin';

  // Fetch certificate statistics
  const { data: allCerts } = useQuery({
    queryKey: ['certificates', 'all'],
    queryFn: () => certificateService.list({ limit: 1000 }),
  });

  const { data: pendingCerts } = useQuery({
    queryKey: ['certificates', 'pending'],
    queryFn: () => certificateService.list({ status: 'pending', limit: 10 }),
  });

  const { data: recentCerts } = useQuery({
    queryKey: ['certificates', 'recent'],
    queryFn: () => certificateService.list({ limit: 5 }),
  });

  const totalCerts = allCerts?.total || 0;
  const pendingCount = pendingCerts?.total || 0;
  const approvedCount = allCerts?.items.filter(c => c.status === 'approved').length || 0;

  const columns: ColumnsType<Certificate> = [
    {
      title: 'Type',
      dataIndex: 'certificate_type',
      key: 'type',
      render: (type) => <CertificateTypeBadge type={type} />,
      width: 120,
    },
    {
      title: 'Common Name',
      dataIndex: 'common_name',
      key: 'common_name',
      ellipsis: true,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status) => <CertificateStatusBadge status={status} />,
      width: 120,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date) => formatDate(date),
      width: 180,
    },
    {
      title: 'Action',
      key: 'action',
      render: (_, record) => (
        <Button type="link" onClick={() => navigate(`/certificates/${record.id}`)}>
          View
        </Button>
      ),
      width: 100,
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>Dashboard</Title>
        <p style={{ color: '#8c8c8c' }}>
          Welcome back, {user?.full_name || user?.username}
        </p>
      </div>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Total Certificates"
              value={totalCerts}
              prefix={<SafetyCertificateOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Approved"
              value={approvedCount}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        {isAdmin && (
          <Col xs={24} sm={12} lg={6}>
            <Card>
              <Statistic
                title="Pending Approval"
                value={pendingCount}
                prefix={<ClockCircleOutlined />}
                valueStyle={{ color: '#faad14' }}
              />
            </Card>
          </Col>
        )}
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Expiring Soon"
              value={0}
              prefix={<ClockCircleOutlined />}
              valueStyle={{ color: '#ff4d4f' }}
              suffix="/ 30 days"
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} md={12}>
          <Card title="Quick Actions" size="small">
            <Space direction="vertical" style={{ width: '100%' }}>
              <Button
                type="primary"
                icon={<FileAddOutlined />}
                onClick={() => navigate('/certificates/request-server')}
                block
              >
                Request Server Certificate
              </Button>
              {isAdmin && (
                <>
                  <Button
                    icon={<LaptopOutlined />}
                    onClick={() => navigate('/certificates/generate-machine')}
                    block
                  >
                    Generate Machine Certificate
                  </Button>
                  <Button
                    icon={<TeamOutlined />}
                    onClick={() => navigate('/certificates/generate-user')}
                    block
                  >
                    Generate User Certificate
                  </Button>
                </>
              )}
              <Button
                icon={<SafetyCertificateOutlined />}
                onClick={() => navigate('/certificates')}
                block
              >
                View All Certificates
              </Button>
            </Space>
          </Card>
        </Col>
        {isAdmin && pendingCount > 0 && (
          <Col xs={24} md={12}>
            <Card 
              title={
                <Space>
                  Pending Approvals
                  <Tag color="warning">{pendingCount}</Tag>
                </Space>
              } 
              size="small"
              extra={<Button type="link" onClick={() => navigate('/approvals')}>View All</Button>}
            >
              <Table
                dataSource={pendingCerts?.items.slice(0, 3)}
                columns={[
                  {
                    title: 'Common Name',
                    dataIndex: 'common_name',
                    key: 'common_name',
                    ellipsis: true,
                  },
                  {
                    title: 'Action',
                    key: 'action',
                    render: (_, record) => (
                      <Button size="small" type="link" onClick={() => navigate(`/certificates/${record.id}`)}>
                        Review
                      </Button>
                    ),
                  },
                ]}
                pagination={false}
                size="small"
                rowKey="id"
              />
            </Card>
          </Col>
        )}
      </Row>

      <Card title="Recent Certificates">
        <Table
          dataSource={recentCerts?.items}
          columns={columns}
          pagination={false}
          rowKey="id"
          loading={!recentCerts}
        />
      </Card>
    </div>
  );
};