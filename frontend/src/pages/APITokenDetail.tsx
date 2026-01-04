import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, Descriptions, Space, Button, Tag, Typography, Modal, Form, Input, message, Alert } from 'antd';
import { ArrowLeftOutlined, DeleteOutlined, EditOutlined, SaveOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiTokenService } from '@/services/apiToken.service';
import { formatDate } from '@/utils/helpers';

const { Title, Text } = Typography;
const { TextArea } = Input;

export const APITokenDetail = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [editMode, setEditMode] = useState(false);
  const [form] = Form.useForm();

  const { data: token, isLoading } = useQuery({
    queryKey: ['apiToken', id],
    queryFn: () => apiTokenService.get(Number(id)),
    enabled: !!id,
  });

  const updateMutation = useMutation({
    mutationFn: (values: any) => apiTokenService.update(Number(id), values),
    onSuccess: () => {
      message.success('Token updated successfully');
      setEditMode(false);
      queryClient.invalidateQueries({ queryKey: ['apiToken', id] });
      queryClient.invalidateQueries({ queryKey: ['apiTokens'] });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: () => apiTokenService.revoke(Number(id)),
    onSuccess: () => {
      message.success('Token revoked successfully');
      navigate('/settings/api-tokens');
    },
  });

  const handleRevoke = () => {
    Modal.confirm({
      title: 'Revoke API Token',
      content: (
        <div>
          <p>Are you sure you want to revoke this token?</p>
          <p style={{ color: '#ff4d4f' }}>
            This action cannot be undone. Any automation using this token will stop working immediately.
          </p>
        </div>
      ),
      okText: 'Revoke',
      okType: 'danger',
      onOk: () => revokeMutation.mutate(),
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

  if (isLoading) {
    return <Card loading />;
  }

  if (!token) {
    return (
      <Card>
        <Alert
          message="Token Not Found"
          description="The requested API token could not be found."
          type="error"
          showIcon
        />
      </Card>
    );
  }

  const isExpired = token.expires_at && new Date(token.expires_at) < new Date();
  const isRevoked = !!token.revoked_at;
  const isActive = token.is_active && !isExpired && !isRevoked;

  return (
    <div>
      <Button
        icon={<ArrowLeftOutlined />}
        onClick={() => navigate('/settings/api-tokens')}
        style={{ marginBottom: 16 }}
      >
        Back to API Tokens
      </Button>

      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 24 }}>
            <div>
              <Title level={3} style={{ marginBottom: 8 }}>
                {token.name}
              </Title>
              <Space>
                {isRevoked ? (
                  <Tag color="error">Revoked</Tag>
                ) : isExpired ? (
                  <Tag color="default">Expired</Tag>
                ) : isActive ? (
                  <Tag color="success">Active</Tag>
                ) : (
                  <Tag color="warning">Inactive</Tag>
                )}
              </Space>
            </div>

            <Space>
              {!editMode && isActive && (
                <>
                  <Button icon={<EditOutlined />} onClick={() => {
                    setEditMode(true);
                    form.setFieldsValue({
                      name: token.name,
                      description: token.description || '',
                    });
                  }}>
                    Edit
                  </Button>
                  <Button
                    danger
                    icon={<DeleteOutlined />}
                    onClick={handleRevoke}
                  >
                    Revoke
                  </Button>
                </>
              )}
              {editMode && (
                <>
                  <Button onClick={() => setEditMode(false)}>
                    Cancel
                  </Button>
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
              <Form.Item
                name="name"
                label="Token Name"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item name="description" label="Description">
                <TextArea rows={3} />
              </Form.Item>
            </Form>
          ) : (
            <Descriptions bordered column={2}>
              <Descriptions.Item label="Token ID" span={2}>
                {token.id}
              </Descriptions.Item>
              <Descriptions.Item label="Name" span={2}>
                {token.name}
              </Descriptions.Item>
              {token.description && (
                <Descriptions.Item label="Description" span={2}>
                  {token.description}
                </Descriptions.Item>
              )}
              <Descriptions.Item label="Scopes" span={2}>
                <Space wrap>
                  {token.scopes && token.scopes.length > 0 ? (
                    token.scopes.map((scope, idx) => <Tag key={idx}>{scope}</Tag>)
                  ) : (
                    <Text type="secondary">No scopes</Text>
                  )}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="Status">
                {isRevoked ? (
                  <Tag color="error">Revoked</Tag>
                ) : isExpired ? (
                  <Tag color="default">Expired</Tag>
                ) : isActive ? (
                  <Tag color="success">Active</Tag>
                ) : (
                  <Tag color="warning">Inactive</Tag>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="Expires At">
                {token.expires_at ? formatDate(token.expires_at) : <Tag>Never</Tag>}
              </Descriptions.Item>
              <Descriptions.Item label="Last Used">
                {token.last_used_at ? formatDate(token.last_used_at) : <Text type="secondary">Never</Text>}
              </Descriptions.Item>
              <Descriptions.Item label="Created">
                {formatDate(token.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label="Created By" span={2}>
                {token.created_by?.username || 'Unknown'} ({token.created_by?.email})
              </Descriptions.Item>
              {token.revoked_at && (
                <>
                  <Descriptions.Item label="Revoked At">
                    {formatDate(token.revoked_at)}
                  </Descriptions.Item>
                  <Descriptions.Item label="Revoked By">
                    {token.revoked_by?.username || 'Unknown'}
                  </Descriptions.Item>
                </>
              )}
            </Descriptions>
          )}
        </Card>

        {isRevoked && (
          <Alert
            message="Token Revoked"
            description="This token has been revoked and can no longer be used for authentication."
            type="error"
            showIcon
          />
        )}

        {isExpired && !isRevoked && (
          <Alert
            message="Token Expired"
            description="This token has expired and can no longer be used for authentication."
            type="warning"
            showIcon
          />
        )}
      </Space>
    </div>
  );
};