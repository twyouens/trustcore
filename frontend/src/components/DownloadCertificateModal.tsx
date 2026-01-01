import { useState } from 'react';
import { Modal, Form, Radio, Input, Alert, Space, Typography } from 'antd';
import { DownloadOutlined } from '@ant-design/icons';
import { OutputFormat } from '@/types';
import { certificateService } from '@/services/certificate.service';
import { downloadBlob, getFileExtension } from '@/utils/helpers';
import { message } from 'antd';

const { Text } = Typography;

interface DownloadCertificateModalProps {
  visible: boolean;
  onCancel: () => void;
  certificateId: number;
  commonName: string;
  certificateType: string;
  defaultPassword?: string;
}

export const DownloadCertificateModal: React.FC<DownloadCertificateModalProps> = ({
  visible,
  onCancel,
  certificateId,
  commonName,
  certificateType,
  defaultPassword,
}) => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [format, setFormat] = useState<OutputFormat>('pem');

  const handleDownload = async () => {
    try {
      setLoading(true);
      const values = await form.validateFields();
      
      const blob = await certificateService.download(certificateId, {
        output_format: values.format,
        pkcs12_password: values.format === 'pkcs12' ? values.password : undefined,
      });

      const extension = getFileExtension(values.format);
      const filename = `${commonName.replace(/[^a-zA-Z0-9]/g, '_')}.${extension}`;
      
      downloadBlob(blob, filename);
      message.success('Certificate downloaded successfully');
      onCancel();
      form.resetFields();
    } catch (error: any) {
      if (error.errorFields) {
        // Validation error, already shown by form
        return;
      }
      message.error('Failed to download certificate');
      console.error('Download error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = () => {
    form.resetFields();
    setFormat('pem');
    onCancel();
  };

  return (
    <Modal
      title={<Space><DownloadOutlined /> Download Certificate</Space>}
      open={visible}
      onOk={handleDownload}
      onCancel={handleCancel}
      confirmLoading={loading}
      okText="Download"
    >
      <Form
        form={form}
        layout="vertical"
        initialValues={{
          format: 'pem',
          password: defaultPassword || '',
        }}
      >
        <Alert
          message="Certificate Information"
          description={
            <Space direction="vertical" size={0}>
              <Text>Common Name: <strong>{commonName}</strong></Text>
              <Text>Type: <strong>{certificateType}</strong></Text>
            </Space>
          }
          type="info"
          style={{ marginBottom: 16 }}
        />

        <Form.Item
          name="format"
          label="Output Format"
          rules={[{ required: true }]}
        >
          <Radio.Group onChange={(e) => setFormat(e.target.value)}>
            <Space direction="vertical">
              <Radio value="pem">
                PEM - Text format, widely compatible
              </Radio>
              <Radio value="pkcs12">
                PKCS12 - Binary format with password protection (.p12)
              </Radio>
              <Radio value="der">
                DER - Binary format (.der)
              </Radio>
            </Space>
          </Radio.Group>
        </Form.Item>

        {format === 'pkcs12' && (
          <>
            <Form.Item
              name="password"
              label="PKCS12 Password"
              extra={
                defaultPassword
                  ? `Leave empty to use default: ${defaultPassword}`
                  : 'Optional password for PKCS12 file'
              }
            >
              <Input.Password placeholder="Enter password (optional)" />
            </Form.Item>
            <Alert
              message="Note"
              description="PKCS12 format includes the CA certificate in the bundle and can be used directly in most applications."
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
            />
          </>
        )}
      </Form>
    </Modal>
  );
};