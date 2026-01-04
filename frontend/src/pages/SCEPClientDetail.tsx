import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Card,
  Descriptions,
  Space,
  Button,
  Tag,
  Typography,
  Modal,
  Form,
  Input,
  Select,
  message,
  Alert,
  Statistic,
  Row,
  Col,
  Progress,
  Divider,
} from 'antd';
import {
  ArrowLeftOutlined,
  DeleteOutlined,
  EditOutlined,
  SaveOutlined,
  CopyOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
} from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scepClientService } from '@/services/scepClient.service';
import { UserBadge } from '@/components/UserBadge';
import { CertificateTypeBadge } from '@/components/CertificateTypeBadge';
import { formatDate, copyToClipboard } from '@/utils/helpers';

const { Title, Text, Paragraph } = Typography;
const { TextArea } = Input;

export const SCEPClientDetail = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [editMode, setEditMode] = useState(false);
  const [form] = Form.useForm();

  const { data: client, isLoading } = useQuery({
    queryKey: ['scepClient', id],
    queryFn: () => scepClientService.get(id!),
    enabled: !!id,
  });

  const updateMutation = useMutation({
    mutationFn: (values: any) => scepClientService.update(id!, values),
    onSuccess: () => {
      message.success('SCEP client updated successfully');
      setEditMode(false);
      queryClient.invalidateQueries({ queryKey: ['scepClient', id] });
      queryClient.invalidateQueries({ queryKey: ['scepClients'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => scepClientService.delete(id!),
    onSuccess: () => {
      message.success('SCEP client deleted successfully');
      navigate('/settings/scep-clients');
    },
  });

  const toggleMutation = useMutation({
    mutationFn: (enabled: boolean) =>
      enabled ? scepClientService.enable(id!) : scepClientService.disable(id!),
    onSuccess: (_, enabled) => {
      message.success(`SCEP client ${enabled ? 'enabled' : 'disabled'} successfully`);
      queryClient.invalidateQueries({ queryKey: ['scepClient', id] });
      queryClient.invalidateQueries({ queryKey: ['scepClients'] });
    },
  });

  const handleDelete = () => {
    Modal.confirm({
      title: 'Delete SCEP Client',
      content: (
        <div>
          <p>Are you sure you want to delete this SCEP client?</p>
          <p style={{ color: '#ff4d4f' }}>
            This will permanently delete the client and its SCEP URL will no longer work.
            This action cannot be undone.
          </p>
        </div>
      ),
      okText: 'Delete',
      okType: 'danger',
      onOk: () => deleteMutation.mutate(),
    });
  };

  const handleUpdate = async () => {
    try {
      const values = await form.validateFields();
      updateMutation.mutate(values);
    } catch (error) {
      // Validation error
    }
  };

  const handleCopyUrl = async (url: string) => {
    const success = await copyToClipboard(url);
    if (success) {
      message.success('SCEP URL copied to clipboard');
    }
  };

  if (isLoading) {
    return <Card loading />;
  }

  if (!client) {
    return (
      <Card>
        <Alert
          message="SCEP Client Not Found"
          description="The requested SCEP client could not be found."
          type="error"
          showIcon
        />
      </Card>
    );
  }

  const successRate = client.total_requests > 0
    ? ((client.successful_requests / client.total_requests) * 100).toFixed(1)
    : 0;

  return (
    <div>
      <Button
        icon={<ArrowLeftOutlined />}
        onClick={() => navigate('/settings/scep-clients')}
        style={{ marginBottom: 16 }}
      >
        Back to SCEP Clients
      </Button>

      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        {/* Header Card */}
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 24 }}>
            <div>
              <Title level={3} style={{ marginBottom: 8 }}>
                {client.name}
              </Title>
              <Space>
                <Tag
                  icon={client.enabled ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
                  color={client.enabled ? 'success' : 'default'}
                >
                  {client.enabled ? 'Enabled' : 'Disabled'}
                </Tag>
                {client.allowed_certificate_types.map((type) => (
                  <CertificateTypeBadge key={type} type={type} />
                ))}
              </Space>
            </div>

            <Space>
              {!editMode && (
                <>
                  <Button
                    type={client.enabled ? 'default' : 'primary'}
                    onClick={() => toggleMutation.mutate(!client.enabled)}
                  >
                    {client.enabled ? 'Disable' : 'Enable'}
                  </Button>
                  <Button
                    icon={<EditOutlined />}
                    onClick={() => {
                      setEditMode(true);
                      form.setFieldsValue({
                        name: client.name,
                        description: client.description || '',
                        allowed_certificate_types: client.allowed_certificate_types,
                        user_validation_url: client.user_validation_url || '',
                        machine_validation_url: client.machine_validation_url || '',
                      });
                    }}
                  >
                    Edit
                  </Button>
                  <Button danger icon={<DeleteOutlined />} onClick={handleDelete}>
                    Delete
                  </Button>
                </>
              )}
              {editMode && (
                <>
                  <Button onClick={() => setEditMode(false)}>Cancel</Button>
                  <Button
                    type="primary"
                    icon={<SaveOutlined />}
                    onClick={handleUpdate}
                    loading={updateMutation.isPending}
                  >
                    Save
                  </Button>
                </>
              )}
            </Space>
          </div>

          {editMode ? (
            <Form form={form} layout="vertical">
              <Form.Item name="name" label="Name" rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              <Form.Item name="description" label="Description">
                <TextArea rows={3} />
              </Form.Item>
              <Form.Item name="allowed_certificate_types" label="Allowed Types" rules={[{ required: true }]}>
                <Select
                  mode="multiple"
                  options={[
                    { label: 'Machine', value: 'machine' },
                    { label: 'User', value: 'user' },
                  ]}
                />
              </Form.Item>
              <Form.Item name="user_validation_url" label="User Validation URL">
                <Input placeholder="https://..." />
              </Form.Item>
              <Form.Item name="machine_validation_url" label="Machine Validation URL">
                <Input placeholder="https://..." />
              </Form.Item>
            </Form>
          ) : (
            <Descriptions bordered column={2}>
              <Descriptions.Item label="Client ID" span={2}>
                <Text code copyable>{client.id}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Name" span={2}>
                {client.name}
              </Descriptions.Item>
              {client.description && (
                <Descriptions.Item label="Description" span={2}>
                  {client.description}
                </Descriptions.Item>
              )}
              <Descriptions.Item label="Allowed Types" span={2}>
                <Space>
                  {client.allowed_certificate_types.map((type, idx) => (
                    <CertificateTypeBadge key={idx} type={type} />
                  ))}
                </Space>
              </Descriptions.Item>
              {client.user_validation_url && (
                <Descriptions.Item label="User Validation URL" span={2}>
                  <Text code copyable style={{ fontSize: 12 }}>
                    {client.user_validation_url}
                  </Text>
                </Descriptions.Item>
              )}
              {client.machine_validation_url && (
                <Descriptions.Item label="Machine Validation URL" span={2}>
                  <Text code copyable style={{ fontSize: 12 }}>
                    {client.machine_validation_url}
                  </Text>
                </Descriptions.Item>
              )}
              <Descriptions.Item label="Created">
                {formatDate(client.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label="Last Updated">
                {formatDate(client.updated_at)}
              </Descriptions.Item>
              <Descriptions.Item label="Created By" span={2}>
                <UserBadge name={client.created_by?.full_name || 'Unknown'} username={client.created_by?.username} />
              </Descriptions.Item>
              <Descriptions.Item label="Last Used" span={2}>
                {client.last_used_at ? formatDate(client.last_used_at) : <Text type="secondary">Never</Text>}
              </Descriptions.Item>
            </Descriptions>
          )}
        </Card>

        {/* SCEP URL Card */}
        <Card title="SCEP Configuration">
          <Alert
            message="Configure this URL in your MDM system"
            description="Use this SCEP URL when configuring certificate enrollment in your MDM (Intune, JAMF, etc.)"
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
          />
          
          <div
            style={{
              background: '#f5f5f5',
              padding: 16,
              borderRadius: 4,
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 13,
              wordBreak: 'break-all',
              position: 'relative',
            }}
          >
            {client.scep_url}
            <Button
              size="small"
              icon={<CopyOutlined />}
              onClick={() => handleCopyUrl(client.scep_url)}
              style={{ position: 'absolute', right: 8, top: 8 }}
            >
              Copy URL
            </Button>
          </div>

          <Divider />

          <Title level={5}>MDM Configuration Examples</Title>
          <Paragraph>
            <strong>Microsoft Intune:</strong>
          </Paragraph>
          <ol>
            <li>Go to Devices → Configuration profiles → Create profile</li>
            <li>Select SCEP certificate profile</li>
            <li>Paste the SCEP URL above into the "SCEP Server URLs" field</li>
            <li>Configure certificate subject and validity</li>
          </ol>

          <Paragraph style={{ marginTop: 16 }}>
            <strong>JAMF Pro:</strong>
          </Paragraph>
          <ol>
            <li>Go to Computers → Configuration Profiles → New</li>
            <li>Add SCEP payload</li>
            <li>Enter the SCEP URL in the URL field</li>
            <li>Configure certificate options</li>
          </ol>
        </Card>

        {/* Statistics Card */}
        <Card title="Usage Statistics">
          <Row gutter={16}>
            <Col span={6}>
              <Statistic title="Total Requests" value={client.total_requests} />
            </Col>
            <Col span={6}>
              <Statistic
                title="Successful"
                value={client.successful_requests}
                valueStyle={{ color: '#52c41a' }}
              />
            </Col>
            <Col span={6}>
              <Statistic
                title="Failed"
                value={client.failed_requests}
                valueStyle={{ color: client.failed_requests > 0 ? '#ff4d4f' : undefined }}
              />
            </Col>
            <Col span={6}>
              <Statistic title="Success Rate" value={`${successRate}%`} />
            </Col>
          </Row>

          <Divider />

          <div>
            <Text strong>Success Rate Visualization</Text>
            <Progress
              percent={Number(successRate)}
              status={Number(successRate) >= 90 ? 'success' : Number(successRate) >= 70 ? 'normal' : 'exception'}
              style={{ marginTop: 8 }}
            />
          </div>
        </Card>
      </Space>
    </div>
  );
};