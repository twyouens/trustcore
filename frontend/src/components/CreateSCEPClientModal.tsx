import { Modal, Form, Input, Select, Switch, Button, Alert, Space, message } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useMutation } from '@tanstack/react-query';
import { scepClientService } from '@/services/scepClient.service';

const { TextArea } = Input;

interface CreateSCEPClientModalProps {
  visible: boolean;
  onCancel: () => void;
  onSuccess: () => void;
}

export const CreateSCEPClientModal: React.FC<CreateSCEPClientModalProps> = ({
  visible,
  onCancel,
  onSuccess,
}) => {
  const [form] = Form.useForm();

  const createMutation = useMutation({
    mutationFn: (values: any) => scepClientService.create(values),
    onSuccess: () => {
      message.success('SCEP client created successfully');
      form.resetFields();
      onSuccess();
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

  const handleCancel = () => {
    form.resetFields();
    onCancel();
  };

  return (
    <Modal
      title="Create SCEP Client"
      open={visible}
      onCancel={handleCancel}
      footer={
        <Space>
          <Button onClick={handleCancel}>Cancel</Button>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={handleCreate}
            loading={createMutation.isPending}
          >
            Create Client
          </Button>
        </Space>
      }
      width={700}
    >
      <Form
        form={form}
        layout="vertical"
        initialValues={{
          enabled: true,
          allowed_certificate_types: ['machine', 'user'],
        }}
      >
        <Alert
          message="SCEP Client for MDM Systems"
          description="Register an MDM system (like Microsoft Intune or JAMF) to enable automated certificate enrollment for devices and users."
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />

        <Form.Item
          name="name"
          label="Client Name"
          rules={[{ required: true, message: 'Please enter a client name' }]}
          tooltip="A descriptive name for this MDM system"
        >
          <Input placeholder="e.g., Intune Production" />
        </Form.Item>

        <Form.Item
          name="description"
          label="Description"
          tooltip="Optional description of what this client is used for"
        >
          <TextArea rows={3} placeholder="e.g., Microsoft Intune for corporate devices" />
        </Form.Item>

        <Form.Item
          name="allowed_certificate_types"
          label="Allowed Certificate Types"
          rules={[{ required: true, message: 'Please select at least one type' }]}
          tooltip="Which certificate types this client can request"
        >
          <Select
            mode="multiple"
            placeholder="Select certificate types"
            options={[
              { label: 'Machine', value: 'machine' },
              { label: 'User', value: 'user' },
            ]}
          />
        </Form.Item>

        <Form.Item
          name="user_validation_url"
          label="User Validation URL (Optional)"
          tooltip="External endpoint to validate user certificate requests"
        >
          <Input placeholder="https://identity.corp.com/api/validate-user" />
        </Form.Item>

        <Form.Item
          name="machine_validation_url"
          label="Machine Validation URL (Optional)"
          tooltip="External endpoint to validate machine certificate requests"
        >
          <Input placeholder="https://cmdb.corp.com/api/validate-mac" />
        </Form.Item>

        <Form.Item
          name="enabled"
          label="Enabled"
          valuePropName="checked"
          tooltip="Whether this client is active and can request certificates"
        >
          <Switch />
        </Form.Item>

        <Alert
          message="After Creating"
          description="You will receive a unique SCEP URL to configure in your MDM system. Make sure to copy it and configure it in your MDM (Intune, JAMF, etc.)."
          type="warning"
          showIcon
        />
      </Form>
    </Modal>
  );
};