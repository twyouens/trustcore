import { useState } from 'react';
import { Card, Table, Select, Space, Button, Typography, Tag } from 'antd';
import { ReloadOutlined, DownloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { auditService } from '@/services/audit.service';
import { formatDate } from '@/utils/helpers';
import { AuditLog } from '@/types';
import type { ColumnsType } from 'antd/es/table';
import { UserBadge } from '@/components/UserBadge';
import dayjs from 'dayjs';

const { Title, Text } = Typography;

export const AuditLogs = () => {
  const [actionFilter, setActionFilter] = useState<string | undefined>();
  const [resourceFilter, setResourceFilter] = useState<string | undefined>();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['audit', actionFilter, resourceFilter, page, pageSize],
    queryFn: () => auditService.list({
      action: actionFilter,
      resource_type: resourceFilter,
      skip: (page - 1) * pageSize,
      limit: pageSize,
    }),
  });

  const columns: ColumnsType<AuditLog> = [
    {
      title: 'Timestamp',
      dataIndex: 'created_at',
      key: 'timestamp',
      width: 180,
      render: (date) => formatDate(date),
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    },
    {
      title: 'Action',
      dataIndex: 'action',
      key: 'action',
      width: 200,
      render: (action) => {
        const colors: Record<string, string> = {
          CREATE: 'blue',
          UPDATE: 'orange',
          DELETE: 'red',
          APPROVE: 'green',
          REJECT: 'red',
          REVOKE: 'volcano',
          DOWNLOAD: 'cyan',
          LOGIN: 'purple',
        };
        const color = Object.keys(colors).find(key => action.includes(key)) || 'default';
        return <Tag color={colors[color as keyof typeof colors] || 'default'}>{action}</Tag>;
      },
    },
    {
      title: 'Resource Type',
      dataIndex: 'resource_type',
      key: 'resource_type',
      width: 150,
      render: (type) => <Tag>{type}</Tag>,
    },
    {
      title: 'Resource ID',
      dataIndex: 'resource_id',
      key: 'resource_id',
      width: 120,
      render: (id) => id || 'N/A',
    },
    {
      title: 'User',
      dataIndex: 'user_id',
      key: 'user',
      width: 150,
      render: (id, user) => id && user.user ? <UserBadge name={user.user.full_name ?? 'N/A'} username={user.user.username ?? 'N/A'} /> : 'System',
    },
    {
      title: 'Details',
      dataIndex: 'details',
      key: 'details',
      ellipsis: true,
      render: (details) => {
        if (!details) return 'N/A';
        const detailsStr = JSON.stringify(details);
        return (
          <Text
            ellipsis={{ tooltip: detailsStr }}
            style={{ maxWidth: 300 }}
          >
            {detailsStr}
          </Text>
        );
      },
    },
  ];

  const exportToCsv = () => {
    if (!data?.items) return;

    const headers = ['Timestamp', 'Action', 'Resource Type', 'Resource ID', 'User ID', 'Username', 'IP Address', 'Details'];
    const rows = data.items.map(log => [
      formatDate(log.created_at),
      log.action,
      log.resource_type,
      log.resource_id || '',
      log.user_id || '',
      log.user?.username || '',
      log.ip_address || '',
      log.details ? JSON.stringify(log.details) : '',
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-logs-${dayjs().format('YYYY-MM-DD')}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>Audit Logs</Title>
        <Text type="secondary">
          Comprehensive tracking of all certificate operations and user activities
        </Text>
      </div>

      <Card>
        <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }} wrap>
          <Space wrap>
            <Select
              placeholder="Filter by action"
              style={{ width: 200 }}
              value={actionFilter}
              onChange={setActionFilter}
              allowClear
              options={[
                { label: 'All Actions', value: undefined },
                { label: 'Certificate Approved', value: 'certificate_approved' },
                { label: 'Certificate Rejected', value: 'certificate_rejected' },
                { label: 'Certificate Revoked', value: 'certificate_revoked' },
                { label: 'Certificate Downloaded', value: 'certificate_downloaded' },
                { label: 'SCEP Request', value: 'scep_request' },
                { label: 'API Token Created', value: 'api_token_created' },
                { label: 'API Token Revoked', value: 'api_token_revoked' },
                { label: 'API Token Updated', value: 'api_token_updated' },
                { label: 'API Token Login Failed', value: 'api_token_login_failed' },
                { label: 'API Token Login Success', value: 'api_token_login_success' },
                { label: 'SCEP Client Created', value: 'scep_client_created' },
                { label: 'SCEP Client Updated', value: 'scep_client_updated' },
                { label: 'SCEP Client Deleted', value: 'scep_client_deleted' },
                { label: 'SCEP Client Disabled', value: 'scep_client_disabled' },
                { label: 'SCEP Client Enabled', value: 'scep_client_enabled' },
                { label: 'SCEP Enrollment Failed', value: 'scep_enrollment_failed' },
                { label: 'SCEP Enrollment Success', value: 'scep_enrollment_success' },
                { label: 'SCEP Enrollment Rejected', value: 'scep_enrollment_rejected' },
                { label: 'SCEP Enrollment Approved', value: 'scep_enrollment_approved' },
                { label: 'Login', value: 'user_login' }
              ]}
            />

            <Select
              placeholder="Filter by resource"
              style={{ width: 200 }}
              value={resourceFilter}
              onChange={setResourceFilter}
              allowClear
              options={[
                { label: 'All Resources', value: undefined },
                { label: 'Certificate', value: 'certificate' },
                { label: 'User', value: 'user' },
                { label: 'CA', value: 'ca' },
                { label: 'API Token', value: 'api_token' },
                { label: 'SCEP Client', value: 'scep_client' }
              ]}
            />
          </Space>

          <Space>
            <Button icon={<DownloadOutlined />} onClick={exportToCsv}>
              Export CSV
            </Button>
            <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
              Refresh
            </Button>
          </Space>
        </Space>

        <Table
          dataSource={data?.items}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{
            current: page,
            pageSize: pageSize,
            total: data?.total || 0,
            showSizeChanger: true,
            showTotal: (total) => `Total ${total} audit entries`,
            pageSizeOptions: ['25', '50', '100', '200'],
            onChange: (newPage, newPageSize) => {
              setPage(newPage);
              setPageSize(newPageSize);
            },
          }}
          scroll={{ x: 1400 }}
          size="small"
        />
      </Card>
    </div>
  );
};