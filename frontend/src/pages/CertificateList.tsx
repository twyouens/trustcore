import { useState } from 'react';
import { Card, Table, Input, Select, Space, Button, Tag, Typography } from 'antd';
import { SearchOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { certificateService } from '@/services/certificate.service';
import { useNavigate } from 'react-router-dom';
import { CertificateStatusBadge } from '@/components/CertificateStatusBadge';
import { CertificateTypeBadge } from '@/components/CertificateTypeBadge';
import { formatDate, formatDateShort, isExpiringSoon, isExpired } from '@/utils/helpers';
import { Certificate, CertificateStatus, CertificateType } from '@/types';
import { useAuthStore } from '@/store/authStore';
import type { ColumnsType } from 'antd/es/table';

const { Title } = Typography;

export const CertificateList = () => {
  const navigate = useNavigate();
  const { user } = useAuthStore();
  const [searchText, setSearchText] = useState('');
  const [statusFilter, setStatusFilter] = useState<CertificateStatus | undefined>();
  const [typeFilter, setTypeFilter] = useState<CertificateType | undefined>();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['certificates', statusFilter, typeFilter, page, pageSize],
    queryFn: () => certificateService.list({
      status: statusFilter,
      certificate_type: typeFilter,
      skip: (page - 1) * pageSize,
      limit: pageSize,
    }),
  });

  // Filter data by search text (client-side for common name)
  const filteredData = data?.items.filter(cert => 
    searchText === '' || cert.common_name.toLowerCase().includes(searchText.toLowerCase())
  ) || [];

  const columns: ColumnsType<Certificate> = [
    {
      title: 'Type',
      dataIndex: 'certificate_type',
      key: 'type',
      width: 120,
      render: (type) => <CertificateTypeBadge type={type} />,
      fixed: 'left',
    },
    {
      title: 'Common Name',
      dataIndex: 'common_name',
      key: 'common_name',
      ellipsis: true,
      render: (name, record) => (
        <Space direction="vertical" size={0}>
          <a onClick={() => navigate(`/certificates/${record.id}`)}>{name}</a>
          {record.subject_alternative_names && record.subject_alternative_names.length > 0 && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              SANs: {record.subject_alternative_names.slice(0, 2).join(', ')}
              {record.subject_alternative_names.length > 2 && ` +${record.subject_alternative_names.length - 2} more`}
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 130,
      render: (status) => <CertificateStatusBadge status={status} />,
    },
    {
      title: 'Serial Number',
      dataIndex: 'serial_number',
      key: 'serial_number',
      width: 200,
      ellipsis: true,
      render: (serial) => (
        <Typography.Text code copyable style={{ fontSize: 12 }}>
          {serial}
        </Typography.Text>
      ),
    },
    {
      title: 'Validity Period',
      key: 'validity',
      width: 220,
      render: (_, record) => {
        if (!record.not_before || !record.not_after) {
          return <Tag color="default">Not issued yet</Tag>;
        }
        
        const expiring = isExpiringSoon(record.not_after);
        const expired = isExpired(record.not_after);
        
        return (
          <Space direction="vertical" size={0}>
            <Typography.Text style={{ fontSize: 12 }}>
              {formatDateShort(record.not_before)} → {formatDateShort(record.not_after)}
            </Typography.Text>
            {expired && <Tag color="error">Expired</Tag>}
            {expiring && !expired && <Tag color="warning">Expiring Soon</Tag>}
          </Space>
        );
      },
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date) => formatDate(date),
    },
    {
      title: 'Auto Approved',
      dataIndex: 'auto_approved',
      key: 'auto_approved',
      width: 120,
      render: (auto) => auto ? <Tag color="blue">Yes</Tag> : <Tag>No</Tag>,
    },
    {
      title: 'Action',
      key: 'action',
      width: 100,
      fixed: 'right',
      render: (_, record) => (
        <Button 
          type="link" 
          size="small"
          onClick={() => navigate(`/certificates/${record.id}`)}
        >
          View
        </Button>
      ),
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>Certificates</Title>
        <Typography.Text type="secondary">
          {user?.role === 'admin' ? 'All certificates in the system' : 'Your certificates'}
        </Typography.Text>
      </div>

      <Card>
        <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }}>
          <Space wrap>
            <Input
              placeholder="Search by common name..."
              prefix={<SearchOutlined />}
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              style={{ width: 250 }}
              allowClear
            />
            
            <Select
              placeholder="Filter by status"
              style={{ width: 160 }}
              value={statusFilter}
              onChange={setStatusFilter}
              allowClear
              options={[
                { label: 'All Status', value: undefined },
                { label: 'Pending', value: 'pending' },
                { label: 'Approved', value: 'approved' },
                { label: 'Rejected', value: 'rejected' },
                { label: 'Revoked', value: 'revoked' },
              ]}
            />
            
            <Select
              placeholder="Filter by type"
              style={{ width: 160 }}
              value={typeFilter}
              onChange={setTypeFilter}
              allowClear
              options={[
                { label: 'All Types', value: undefined },
                { label: 'Machine', value: 'machine' },
                { label: 'User', value: 'user' },
                { label: 'Server', value: 'server' },
              ]}
            />
          </Space>

          <Button 
            icon={<ReloadOutlined />} 
            onClick={() => refetch()}
          >
            Refresh
          </Button>
        </Space>

        <Table
          dataSource={filteredData}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{
            current: page,
            pageSize: pageSize,
            total: data?.total || 0,
            showSizeChanger: true,
            showTotal: (total) => `Total ${total} certificates`,
            pageSizeOptions: ['10', '25', '50', '100'],
            onChange: (newPage, newPageSize) => {
              setPage(newPage);
              setPageSize(newPageSize);
            },
          }}
          scroll={{ x: 1400 }}
        />
      </Card>
    </div>
  );
};