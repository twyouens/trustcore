import { useState } from 'react';
import { Card, Table, Button, Space, Tag, Typography, Switch, Modal, message, Progress, Tooltip } from 'antd';
import {
  PlusOutlined,
  ReloadOutlined,
  DeleteOutlined,
  EyeOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
} from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scepClientService } from '@/services/scepClient.service';
import { useNavigate } from 'react-router-dom';
import { formatDate } from '@/utils/helpers';
import type { SCEPClient, CertificateType } from '@/types';
import type { ColumnsType } from 'antd/es/table';
import { CreateSCEPClientModal } from '@/components/CreateSCEPClientModal';
import { CertificateTypeBadge } from '@/components/CertificateTypeBadge';

const { Title, Text } = Typography;

export const SCEPClients = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [includeDisabled, setIncludeDisabled] = useState(false);
  const [createModalVisible, setCreateModalVisible] = useState(false);

  const { data: clients, isLoading, refetch } = useQuery({
    queryKey: ['scepClients', includeDisabled],
    queryFn: () => scepClientService.list(includeDisabled),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => scepClientService.delete(id),
    onSuccess: () => {
      message.success('SCEP client deleted successfully');
      queryClient.invalidateQueries({ queryKey: ['scepClients'] });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      enabled ? scepClientService.enable(id) : scepClientService.disable(id),
    onSuccess: (_, variables) => {
      message.success(`SCEP client ${variables.enabled ? 'enabled' : 'disabled'} successfully`);
      queryClient.invalidateQueries({ queryKey: ['scepClients'] });
    },
  });

  const handleDelete = (client: SCEPClient) => {
    Modal.confirm({
      title: 'Delete SCEP Client',
      content: (
        <div>
          <p>Are you sure you want to delete this SCEP client?</p>
          <p><strong>Name:</strong> {client.name}</p>
          <p style={{ color: '#ff4d4f' }}>
            This will permanently delete the client and its SCEP URL will no longer work.
            This action cannot be undone.
          </p>
        </div>
      ),
      okText: 'Delete',
      okType: 'danger',
      onOk: () => deleteMutation.mutate(client.id),
    });
  };

  const columns: ColumnsType<SCEPClient> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name, record) => (
        <Space direction="vertical" size={0}>
          <a onClick={() => navigate(`/settings/scep-clients/${record.id}`)}>{name}</a>
          {record.description && (
            <Text type="secondary" style={{ fontSize: 12 }}>
              {record.description}
            </Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Allowed Types',
      dataIndex: 'allowed_certificate_types',
      key: 'types',
      width: 200,
      render: (types: CertificateType[]) => (
        <Space wrap>
          {types.map((type, idx) => (
            <CertificateTypeBadge key={idx} type={type} />
          ))}
        </Space>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'enabled',
      key: 'status',
      width: 100,
      render: (enabled) => (
        <Tag icon={enabled ? <CheckCircleOutlined /> : <CloseCircleOutlined />} color={enabled ? 'success' : 'default'}>
          {enabled ? 'Enabled' : 'Disabled'}
        </Tag>
      ),
    },
    {
      title: 'Usage Stats',
      key: 'stats',
      width: 200,
      render: (_, record) => {
        const successRate = record.total_requests > 0
          ? ((record.successful_requests / record.total_requests) * 100).toFixed(1)
          : 0;
        return (
          <Space direction="vertical" size={0} style={{ width: '100%' }}>
            <Text style={{ fontSize: 12 }}>
              {record.total_requests} requests ({record.successful_requests} success)
            </Text>
            <Progress
              percent={Number(successRate)}
              size="small"
              status={Number(successRate) >= 90 ? 'success' : Number(successRate) >= 70 ? 'normal' : 'exception'}
            />
          </Space>
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
      title: 'Actions',
      key: 'actions',
      width: 180,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Tooltip title="View Details">
            <Button
              type="link"
              size="small"
              icon={<EyeOutlined />}
              onClick={() => navigate(`/settings/scep-clients/${record.id}`)}
            />
          </Tooltip>
          <Switch
            checked={record.enabled}
            onChange={(checked) => toggleMutation.mutate({ id: record.id, enabled: checked })}
            size="small"
          />
          <Tooltip title="Delete">
            <Button
              type="link"
              size="small"
              danger
              icon={<DeleteOutlined />}
              onClick={() => handleDelete(record)}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>SCEP Clients</Title>
        <Text type="secondary">
          Manage MDM systems (Intune, JAMF) for automated certificate enrollment
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
              Create SCEP Client
            </Button>
            <Space>
              <Text>Show disabled:</Text>
              <Switch
                checked={includeDisabled}
                onChange={setIncludeDisabled}
              />
            </Space>
          </Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
            Refresh
          </Button>
        </Space>

        <Table
          dataSource={clients}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `Total ${total} clients`,
          }}
          scroll={{ x: 1400 }}
        />
      </Card>

      <CreateSCEPClientModal
        visible={createModalVisible}
        onCancel={() => setCreateModalVisible(false)}
        onSuccess={() => {
          setCreateModalVisible(false);
          queryClient.invalidateQueries({ queryKey: ['scepClients'] });
        }}
      />
    </div>
  );
};