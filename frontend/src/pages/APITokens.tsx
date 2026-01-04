import { useState } from 'react';
import { Card, Table, Button, Space, Tag, Typography, Switch, Modal, message, Tooltip } from 'antd';
import { PlusOutlined, ReloadOutlined, DeleteOutlined, EyeOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiTokenService } from '@/services/apiToken.service';
import { useNavigate } from 'react-router-dom';
import { formatDate } from '@/utils/helpers';
import { APIToken } from '@/types';
import type { ColumnsType } from 'antd/es/table';
import { CreateAPITokenModal } from '@/components/CreateAPITokenModal';

const { Title, Text } = Typography;

export const APITokens = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [includeInactive, setIncludeInactive] = useState(false);
  const [createModalVisible, setCreateModalVisible] = useState(false);

  const { data: tokens, isLoading, refetch } = useQuery({
    queryKey: ['apiTokens', includeInactive],
    queryFn: () => apiTokenService.list(includeInactive),
  });

  const revokeMutation = useMutation({
    mutationFn: (id: number) => apiTokenService.revoke(id),
    onSuccess: () => {
      message.success('API token revoked successfully');
      queryClient.invalidateQueries({ queryKey: ['apiTokens'] });
    },
  });

  const handleRevoke = (token: APIToken) => {
    Modal.confirm({
      title: 'Revoke API Token',
      content: (
        <div>
          <p>Are you sure you want to revoke this token?</p>
          <p><strong>Name:</strong> {token.name}</p>
          <p style={{ color: '#ff4d4f' }}>
            This action cannot be undone. Any automation using this token will stop working immediately.
          </p>
        </div>
      ),
      okText: 'Revoke',
      okType: 'danger',
      onOk: () => revokeMutation.mutate(token.id),
    });
  };

  const columns: ColumnsType<APIToken> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name, record) => (
        <Space direction="vertical" size={0}>
          <a onClick={() => navigate(`/settings/api-tokens/${record.id}`)}>{name}</a>
          {record.description && (
            <Text type="secondary" style={{ fontSize: 12 }}>
              {record.description}
            </Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Scopes',
      dataIndex: 'scopes',
      key: 'scopes',
      width: 250,
      render: (scopes: string[]) => (
        <Space wrap>
          {scopes && scopes.length > 0 ? (
            scopes.map((scope, idx) => <Tag key={idx}>{scope}</Tag>)
          ) : (
            <Text type="secondary">No scopes</Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'status',
      width: 100,
      render: (isActive, record) => {
        if (record.revoked_at) {
          return <Tag color="error">Revoked</Tag>;
        }
        if (record.expires_at && new Date(record.expires_at) < new Date()) {
          return <Tag color="default">Expired</Tag>;
        }
        return isActive ? <Tag color="success">Active</Tag> : <Tag color="warning">Inactive</Tag>;
      },
    },
    {
      title: 'Expires',
      dataIndex: 'expires_at',
      key: 'expires',
      width: 180,
      render: (date) => {
        if (!date) return <Tag>Never</Tag>;
        const isExpired = new Date(date) < new Date();
        return (
          <Tooltip title={formatDate(date)}>
            <Tag color={isExpired ? 'error' : 'default'}>
              {isExpired ? 'Expired' : formatDate(date)}
            </Tag>
          </Tooltip>
        );
      },
    },
    {
      title: 'Last Used',
      dataIndex: 'last_used_at',
      key: 'last_used',
      width: 180,
      render: (date) => date ? formatDate(date) : <Text type="secondary">Never</Text>,
    },
    {
      title: 'Created By',
      dataIndex: 'created_by',
      key: 'created_by',
      width: 150,
      render: (createdBy) => createdBy?.username || 'Unknown',
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 150,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Tooltip title="View Details">
            <Button
              type="link"
              size="small"
              icon={<EyeOutlined />}
              onClick={() => navigate(`/settings/api-tokens/${record.id}`)}
            />
          </Tooltip>
          {record.is_active && !record.revoked_at && (
            <Tooltip title="Revoke">
              <Button
                type="link"
                size="small"
                danger
                icon={<DeleteOutlined />}
                onClick={() => handleRevoke(record)}
              />
            </Tooltip>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>API Tokens</Title>
        <Text type="secondary">
          Create long-lived tokens for automation and API access
        </Text>
      </div>

      <Card>
        <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }}>
          <Space>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setCreateModalVisible(true)}
            >
              Create Token
            </Button>
            <Space>
              <Text>Show inactive:</Text>
              <Switch
                checked={includeInactive}
                onChange={setIncludeInactive}
              />
            </Space>
          </Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
            Refresh
          </Button>
        </Space>

        <Table
          dataSource={tokens}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `Total ${total} tokens`,
          }}
          scroll={{ x: 1400 }}
        />
      </Card>

      <CreateAPITokenModal
        visible={createModalVisible}
        onCancel={() => setCreateModalVisible(false)}
        onSuccess={() => {
          setCreateModalVisible(false);
          queryClient.invalidateQueries({ queryKey: ['apiTokens'] });
        }}
      />
    </div>
  );
};