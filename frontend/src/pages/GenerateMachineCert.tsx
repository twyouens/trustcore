import { useState } from 'react';
import { Card, Form, Input, Slider, Select, Button, Alert, Space, Typography, Divider, message } from 'antd';
import { LaptopOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { certificateService } from '@/services/certificate.service';
import { formatMacAddress, validateMacAddress } from '@/utils/helpers';
import { MandatoryDownloadModal } from '@/components/MandatoryDownloadModal';

const { Title, Text } = Typography;

export const GenerateMachineCert = () => {
  const navigate = useNavigate();
  const [form] = Form.useForm();
  const [useDefaultPassword, setUseDefaultPassword] = useState(true);
  const [generatedCert, setGeneratedCert] = useState<any>(null);
  const [showDownloadModal, setShowDownloadModal] = useState(false);

  const generateMutation = useMutation({
    mutationFn: (values: any) => certificateService.generateMachine({
      mac_address: values.mac_address,
      validity_days: values.validity_days,
      output_format: values.output_format,
      pkcs12_password: values.output_format === 'pkcs12' && !useDefaultPassword ? values.pkcs12_password : undefined,
    }),
    onSuccess: (data) => {
      message.success('Machine certificate generated successfully');
      setGeneratedCert(data);
      setShowDownloadModal(true);
    },
  });

  const handleSubmit = (values: any) => {
    if (!validateMacAddress(values.mac_address)) {
      message.error('Please provide a valid MAC address');
      return;
    }
    generateMutation.mutate(values);
  };

  const handleDownloadComplete = () => {
    setShowDownloadModal(false);
    navigate(`/certificates/${generatedCert.id}`);
  };

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>Generate Machine Certificate</Title>
        <Text type="secondary">
          Create a certificate for device WiFi authentication (EAP-TLS)
        </Text>
      </div>

      <Card>
        <Alert
          message="Machine Certificates"
          description={
            <ul style={{ marginBottom: 0, paddingLeft: 20 }}>
              <li>Used for device authentication on WiFi networks using 802.1X EAP-TLS</li>
              <li>Identified by MAC address</li>
              <li>Certificate is automatically approved upon generation</li>
              <li>Includes both certificate and private key</li>
            </ul>
          }
          type="info"
          showIcon
          style={{ marginBottom: 24 }}
        />

        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          initialValues={{
            validity_days: 365,
            output_format: 'pkcs12',
          }}
        >
          <Form.Item
            name="mac_address"
            label="MAC Address"
            rules={[
              { required: true, message: 'Please provide a MAC address' },
              {
                validator: (_, value) => {
                  if (value && !validateMacAddress(value)) {
                    return Promise.reject('Invalid MAC address format');
                  }
                  return Promise.resolve();
                },
              },
            ]}
            tooltip="Format: AA:BB:CC:DD:EE:FF"
          >
            <Input
              placeholder="AA:BB:CC:DD:EE:FF"
              onChange={(e) => {
                const formatted = formatMacAddress(e.target.value);
                form.setFieldValue('mac_address', formatted);
              }}
              maxLength={17}
              style={{ fontFamily: 'JetBrains Mono, monospace' }}
            />
          </Form.Item>

          <Divider />

          <Form.Item
            name="validity_days"
            label="Validity Period (Days)"
            tooltip="How long the certificate will be valid"
          >
            <Slider
              min={1}
              max={3650}
              marks={{
                1: '1 day',
                365: '1 year',
                730: '2 years',
                1825: '5 years',
                3650: '10 years',
              }}
              tooltip={{ formatter: (value) => `${value} days` }}
            />
          </Form.Item>

          <Form.Item
            name="output_format"
            label="Output Format"
            tooltip="Format for certificate download"
          >
            <Select
              options={[
                { label: 'PKCS12 - Binary format with password (.p12) - Recommended', value: 'pkcs12' },
                { label: 'PEM - Text format', value: 'pem' },
                { label: 'DER - Binary format (.der)', value: 'der' },
              ]}
            />
          </Form.Item>

          <Form.Item
            noStyle
            shouldUpdate={(prevValues, currentValues) => prevValues.output_format !== currentValues.output_format}
          >
            {({ getFieldValue }) =>
              getFieldValue('output_format') === 'pkcs12' && (
                <>
                  <Form.Item>
                    <Space>
                      <input
                        type="checkbox"
                        checked={useDefaultPassword}
                        onChange={(e) => setUseDefaultPassword(e.target.checked)}
                        id="use-default-password"
                      />
                      <label htmlFor="use-default-password">
                        Use default password (MAC address)
                      </label>
                    </Space>
                  </Form.Item>

                  {!useDefaultPassword && (
                    <Form.Item
                      name="pkcs12_password"
                      label="PKCS12 Password"
                      rules={[
                        { required: true, message: 'Please provide a password' },
                        { min: 4, message: 'Password must be at least 4 characters' },
                      ]}
                    >
                      <Input.Password placeholder="Enter password for PKCS12 file" />
                    </Form.Item>
                  )}

                  <Alert
                    message="PKCS12 Format (Recommended)"
                    description="PKCS12 format bundles the certificate, private key, and CA certificate in a single password-protected file. This is the preferred format for most WiFi configurations."
                    type="success"
                    showIcon
                    style={{ marginBottom: 16 }}
                  />
                </>
              )
            }
          </Form.Item>

          <Divider />

          <Form.Item>
            <Space>
              <Button
                type="primary"
                htmlType="submit"
                icon={<LaptopOutlined />}
                loading={generateMutation.isPending}
                size="large"
              >
                Generate Certificate
              </Button>
              <Button onClick={() => navigate('/certificates')} size="large">
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Card>

      {generatedCert && (
        <MandatoryDownloadModal
          visible={showDownloadModal}
          certificateData={generatedCert.certificate}
          certificateType={generatedCert.certificate_type}
          commonName={generatedCert.common_name}
          outputFormat={form.getFieldValue('output_format')}
          onDownloadComplete={handleDownloadComplete}
        />
      )}
    </div>
  );
};