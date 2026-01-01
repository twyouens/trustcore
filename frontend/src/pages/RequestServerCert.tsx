import { useState } from 'react';
import { Card, Form, Input, Slider, Select, Button, Alert, Space, Typography, Divider, message } from 'antd';
import { FileAddOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { certificateService } from '@/services/certificate.service';
import { validateCSR } from '@/utils/helpers';

const { Title, Text } = Typography;
const { TextArea } = Input;

export const RequestServerCert = () => {
  const navigate = useNavigate();
  const [form] = Form.useForm();
  const [csrValid, setCsrValid] = useState<boolean | null>(null);
  const [useDefaultPassword, setUseDefaultPassword] = useState(true);

  const requestMutation = useMutation({
    mutationFn: (values: any) => certificateService.requestServer({
      csr: values.csr,
      validity_days: values.validity_days,
      output_format: values.output_format,
      pkcs12_password: values.output_format === 'pkcs12' && !useDefaultPassword ? values.pkcs12_password : undefined,
    }),
    onSuccess: (data) => {
      message.success('Certificate request submitted successfully');
      navigate(`/certificates/${data.id}`);
    },
  });

  const handleCsrChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const csr = e.target.value;
    if (csr) {
      const isValid = validateCSR(csr);
      setCsrValid(isValid);
    } else {
      setCsrValid(null);
    }
  };

  const handleSubmit = (values: any) => {
    if (!validateCSR(values.csr)) {
      message.error('Please provide a valid CSR');
      return;
    }
    requestMutation.mutate(values);
  };

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>Request Server Certificate</Title>
        <Text type="secondary">
          Submit a Certificate Signing Request (CSR) for SSL/TLS server authentication
        </Text>
      </div>

      <Card>
        <Alert
          message="Before You Begin"
          description={
            <ul style={{ marginBottom: 0, paddingLeft: 20 }}>
              <li>Generate a CSR using OpenSSL or your web server</li>
              <li>The CSR must include the Common Name (CN) and optionally Subject Alternative Names (SANs)</li>
              <li>Your certificate request will be pending until an administrator approves it</li>
              <li>You will be able to download the certificate once approved</li>
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
            output_format: 'pem',
          }}
        >
          <Form.Item
            name="csr"
            label="Certificate Signing Request (CSR)"
            rules={[
              { required: true, message: 'Please provide a CSR' },
              {
                validator: (_, value) => {
                  if (value && !validateCSR(value)) {
                    return Promise.reject('Invalid CSR format');
                  }
                  return Promise.resolve();
                },
              },
            ]}
            help={
              csrValid === true ? (
                <Text type="success">
                  <CheckCircleOutlined /> Valid CSR format detected
                </Text>
              ) : csrValid === false ? (
                <Text type="danger">Invalid CSR format. Must be PEM encoded.</Text>
              ) : (
                'Paste your PEM encoded CSR (including BEGIN and END markers)'
              )
            }
          >
            <TextArea
              rows={12}
              placeholder="-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----"
              onChange={handleCsrChange}
              style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}
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
            tooltip="Format for certificate download after approval"
          >
            <Select
              options={[
                { label: 'PEM - Text format, widely compatible', value: 'pem' },
                { label: 'PKCS12 - Binary format with password (.p12)', value: 'pkcs12' },
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
                        Use default password (your username)
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
                    message="PKCS12 Format"
                    description="PKCS12 format includes the CA certificate in the bundle and can be imported directly into most systems."
                    type="info"
                    showIcon
                    style={{ marginBottom: 16 }}
                  />
                </>
              )
            }
          </Form.Item>

          <Divider />

          <Alert
            message="How to Generate a CSR"
            description={
              <div>
                <p>Using OpenSSL:</p>
                <pre style={{ background: '#f5f5f5', padding: 8, borderRadius: 4, fontSize: 12 }}>
                  openssl req -new -newkey rsa:2048 -nodes \{'\n'}
                  {'  '}-keyout server.key -out server.csr \{'\n'}
                  {'  '}-subj "/CN=example.com" \{'\n'}
                  {'  '}-addext "subjectAltName=DNS:example.com,DNS:www.example.com"
                </pre>
                <p style={{ marginTop: 8, marginBottom: 0 }}>
                  <strong>Important:</strong> Keep your private key (server.key) secure! You'll need it when installing the certificate.
                </p>
              </div>
            }
            type="warning"
            showIcon
            style={{ marginBottom: 24 }}
          />

          <Form.Item>
            <Space>
              <Button
                type="primary"
                htmlType="submit"
                icon={<FileAddOutlined />}
                loading={requestMutation.isPending}
                size="large"
              >
                Submit Request
              </Button>
              <Button onClick={() => navigate('/certificates')} size="large">
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
};