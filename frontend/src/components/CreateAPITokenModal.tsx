import { useState } from 'react';
import { Modal, Form, Input, InputNumber, Select, Button, Alert, Space, Typography, message, Divider } from 'antd';
import { PlusOutlined, CopyOutlined, CheckCircleOutlined, WarningOutlined } from '@ant-design/icons';
import { useMutation } from '@tanstack/react-query';
import { apiTokenService } from '@/services/apiToken.service';
import { copyToClipboard } from '@/utils/helpers';
import { getApiBaseUrl } from '@/services/api';

const { Title, Paragraph } = Typography;
const { TextArea } = Input;

interface CreateAPITokenModalProps {
  visible: boolean;
  onCancel: () => void;
  onSuccess: () => void;
}

const SCOPE_OPTIONS = [
  { label: 'certificates:read', value: 'certificates:read' },
  { label: 'certificates:write', value: 'certificates:write' },
  { label: 'certificates:approve', value: 'certificates:approve' },
  { label: 'certificates:revoke', value: 'certificates:revoke' },
];

export const CreateAPITokenModal: React.FC<CreateAPITokenModalProps> = ({
  visible,
  onCancel,
  onSuccess,
}) => {
  const [form] = Form.useForm();
  const [createdToken, setCreatedToken] = useState<string | null>(null);
  const [tokenCopied, setTokenCopied] = useState(false);
  const [showTokenStage, setShowTokenStage] = useState(false);

  const createMutation = useMutation({
    mutationFn: (values: any) => apiTokenService.create(values),
    onSuccess: (data) => {
      message.success('API token created successfully');
      setCreatedToken(data.token);
      setShowTokenStage(true);
    },
  });

  const handleCreate = async () => {
    try {
      const values = await form.validateFields();
      createMutation.mutate(values);
    } catch (error) {
      // Validation error
    }
  };

  const handleCopyToken = async () => {
    if (createdToken) {
      const success = await copyToClipboard(createdToken);
      if (success) {
        setTokenCopied(true);
        message.success('Token copied to clipboard');
      } else {
        message.error('Failed to copy token');
      }
    }
  };

  const handleClose = () => {
    if (showTokenStage && !tokenCopied) {
      message.warning('Please copy the token before closing');
      return;
    }

    // Reset state
    form.resetFields();
    setCreatedToken(null);
    setTokenCopied(false);
    setShowTokenStage(false);
    
    if (showTokenStage) {
      onSuccess();
    } else {
      onCancel();
    }
  };

  const apiBaseUrl = getApiBaseUrl();

  return (
    <Modal
      title={
        showTokenStage ? (
          <Space>
            <WarningOutlined style={{ color: '#faad14' }} />
            <span>Save Your API Token</span>
          </Space>
        ) : (
          'Create API Token'
        )
      }
      open={visible}
      onCancel={handleClose}
      closable={!showTokenStage || tokenCopied}
      maskClosable={false}
      keyboard={false}
      footer={
        showTokenStage ? (
          <Space>
            <Button
              type="primary"
              icon={tokenCopied ? <CheckCircleOutlined /> : <CopyOutlined />}
              onClick={handleCopyToken}
              disabled={tokenCopied}
            >
              {tokenCopied ? 'Copied' : 'Copy Token'}
            </Button>
            {tokenCopied && (
              <Button onClick={handleClose}>
                Continue
              </Button>
            )}
          </Space>
        ) : (
          <Space>
            <Button onClick={handleClose}>Cancel</Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={handleCreate}
              loading={createMutation.isPending}
            >
              Create Token
            </Button>
          </Space>
        )
      }
      width={700}
    >
      {!showTokenStage ? (
        // Stage 1: Create Form
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            scopes: ['certificates:read'],
          }}
        >
          <Alert
            message="API Token for Automation"
            description="Create a long-lived token that automation systems can use to authenticate with the TrustCore API without requiring interactive login. Tokens created are associated with the user who created them and their permissions."
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
          />

          <Form.Item
            name="name"
            label="Token Name"
            rules={[{ required: true, message: 'Please enter a token name' }]}
            tooltip="A descriptive name to identify this token"
          >
            <Input placeholder="e.g., CI/CD Pipeline Token" />
          </Form.Item>

          <Form.Item
            name="description"
            label="Description"
            tooltip="Optional description of what this token is used for"
          >
            <TextArea rows={3} placeholder="e.g., Token for automated certificate generation in Jenkins" />
          </Form.Item>

          <Form.Item
            name="scopes"
            label="Scopes"
            tooltip="Permission scopes (for future use)"
          >
            <Select
              mode="multiple"
              placeholder="Select scopes"
              options={SCOPE_OPTIONS}
            />
          </Form.Item>

          <Form.Item
            name="expires_in_days"
            label="Expires In (Days)"
            tooltip="Leave empty for no expiration. Maximum 3650 days (10 years)"
          >
            <InputNumber
              min={1}
              max={3650}
              placeholder="Leave empty for no expiration"
              style={{ width: '100%' }}
            />
          </Form.Item>
        </Form>
      ) : (
        // Stage 2: Display Token (Mandatory Copy)
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <Alert
            message="⚠️ Important: One-Time Display"
            description={
              <div>
                <Paragraph style={{ marginBottom: 8 }}>
                  This token will <strong>only be shown once</strong> for security reasons.
                  You must copy it now before closing this window.
                </Paragraph>
                <Paragraph style={{ marginBottom: 0 }}>
                  <strong>Copy and store it in a secure location.</strong>
                </Paragraph>
              </div>
            }
            type="warning"
            showIcon
          />

          <div>
            <Title level={5}>Your API Token</Title>
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
              {createdToken}
              <Button
                size="small"
                icon={<CopyOutlined />}
                onClick={handleCopyToken}
                style={{ position: 'absolute', right: 8, top: 8 }}
              >
                Copy
              </Button>
            </div>
          </div>

          <Divider />

          <div>
            <Title level={5}>How to Use This Token</Title>
            <Paragraph>
              1. <strong>Exchange token for JWT:</strong>
            </Paragraph>
            <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4, fontSize: 12 }}>
{`curl -X POST ${apiBaseUrl}/api/v1/auth/token-login \\
  -H "Content-Type: application/json" \\
  -d '{
    "api_token": "${createdToken?.substring(0, 20)}..."
  }'`}
            </pre>

            <Paragraph style={{ marginTop: 16 }}>
              2. <strong>Use the returned JWT for subsequent API calls:</strong>
            </Paragraph>
            <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4, fontSize: 12 }}>
{`curl -X GET ${apiBaseUrl}/api/v1/certificates \\
  -H "Authorization: Bearer <jwt_token>"`}
            </pre>

            <Alert
              message="Security Best Practices"
              description={
                <ul style={{ marginBottom: 0, paddingLeft: 20 }}>
                  <li>Store the token in a secure secrets management system</li>
                  <li>Never commit the token to version control</li>
                  <li>Rotate tokens regularly</li>
                  <li>Revoke tokens that are no longer needed</li>
                </ul>
              }
              type="info"
              showIcon
              style={{ marginTop: 16 }}
            />
          </div>

          {tokenCopied && (
            <Alert
              message="✅ Token Copied Successfully"
              description="You can now close this window and use the token in your automation."
              type="success"
              showIcon
            />
          )}
        </Space>
      )}
    </Modal>
  );
};