import { Card, Descriptions, Button, Space, Typography, Alert, Tabs, Divider, Input } from 'antd';
import { DownloadOutlined, CopyOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { caService } from '@/services/ca.service';
import { formatDate, downloadText, copyToClipboard } from '@/utils/helpers';
import { getCrlUrl, getCaCertificateUrl, getOcspUrl } from '@/utils/apiUrls';
import { message } from 'antd';

const { Title, Text, Paragraph } = Typography;

export const CAInformation = () => {
  const { data: caInfo, isLoading: infoLoading } = useQuery({
    queryKey: ['ca', 'info'],
    queryFn: () => caService.getInfo(),
  });

  const { data: caCert, isLoading: certLoading } = useQuery({
    queryKey: ['ca', 'certificate'],
    queryFn: () => caService.getCertificate(),
  });

  const { data: crl, isLoading: crlLoading } = useQuery({
    queryKey: ['ca', 'crl'],
    queryFn: () => caService.getCRL(),
  });

  const handleDownloadCert = () => {
    if (caCert) {
      downloadText(caCert, 'ca-certificate.pem');
      message.success('CA certificate downloaded');
    }
  };

  const handleDownloadCRL = () => {
    if (crl) {
      downloadText(crl, 'ca-crl.pem');
      message.success('CRL downloaded');
    }
  };

  const handleCopyCert = async () => {
    if (caCert) {
      const success = await copyToClipboard(caCert);
      if (success) {
        message.success('CA certificate copied to clipboard');
      }
    }
  };

  const handleCopyCrlUrl = async () => {
    const crlUrl = getCrlUrl();
    const success = await copyToClipboard(crlUrl);
    if (success) {
      message.success('CRL URL copied to clipboard');
    }
  };

  const handleCopyCaCertUrl = async () => {
    const caCertUrl = getCaCertificateUrl();
    const success = await copyToClipboard(caCertUrl);
    if (success) {
      message.success('CA Certificate URL copied to clipboard');
    }
  };

  const handleCopyOcspUrl = async () => {
    const ocspUrl = getOcspUrl();
    const success = await copyToClipboard(ocspUrl);
    if (success) {
      message.success('OCSP URL copied to clipboard');
    }
  };

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>Certificate Authority Information</Title>
        <Text type="secondary">
          View and download CA certificate and Certificate Revocation List
        </Text>
      </div>

      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <Card title="CA Details" loading={infoLoading}>
          {caInfo && (
            <Descriptions bordered column={2}>
              <Descriptions.Item label="Subject" span={2}>
                {caInfo.subject}
              </Descriptions.Item>
              <Descriptions.Item label="Issuer" span={2}>
                {caInfo.issuer}
              </Descriptions.Item>
              <Descriptions.Item label="Serial Number">
                <Text code copyable>{caInfo.serial_number}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Key Size">
                {caInfo.key_size} bits
              </Descriptions.Item>
              <Descriptions.Item label="Valid From">
                {formatDate(caInfo.not_before)}
              </Descriptions.Item>
              <Descriptions.Item label="Valid Until">
                {formatDate(caInfo.not_after)}
              </Descriptions.Item>
              <Descriptions.Item label="Signature Algorithm" span={2}>
                {caInfo.signature_algorithm}
              </Descriptions.Item>
            </Descriptions>
          )}
        </Card>

        <Card title="Downloads">
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <div>
              <Title level={5}>CA Certificate</Title>
              <Paragraph type="secondary">
                Download the CA certificate to install on your devices for trust validation
              </Paragraph>
              <Space direction="vertical" style={{ width: '100%' }}>
                <Space>
                  <Button
                    type="primary"
                    icon={<DownloadOutlined />}
                    onClick={handleDownloadCert}
                    loading={certLoading}
                  >
                    Download CA Certificate (PEM)
                  </Button>
                  <Button
                    icon={<CopyOutlined />}
                    onClick={handleCopyCert}
                    loading={certLoading}
                  >
                    Copy Certificate
                  </Button>
                </Space>
                <Input
                  readOnly
                  value={getCaCertificateUrl()}
                  addonAfter={
                    <Button
                      type="text"
                      size="small"
                      icon={<CopyOutlined />}
                      onClick={handleCopyCaCertUrl}
                    >
                      Copy URL
                    </Button>
                  }
                />
              </Space>
            </div>

            <Divider />

            <div>
              <Title level={5}>Certificate Revocation List (CRL)</Title>
              <Paragraph type="secondary">
                Download the CRL to check which certificates have been revoked
              </Paragraph>
              <Space direction="vertical" style={{ width: '100%' }}>
                <Button
                  icon={<DownloadOutlined />}
                  onClick={handleDownloadCRL}
                  loading={crlLoading}
                >
                  Download CRL (PEM)
                </Button>
                <Input
                  readOnly
                  value={getCrlUrl()}
                  addonAfter={
                    <Button
                      type="text"
                      size="small"
                      icon={<CopyOutlined />}
                      onClick={handleCopyCrlUrl}
                    >
                      Copy URL
                    </Button>
                  }
                />
              </Space>
            </div>

            <Divider />

            <div>
              <Title level={5}>OCSP Responder</Title>
              <Paragraph type="secondary">
                Real-time certificate status checking (alternative to CRL)
              </Paragraph>
              <Space direction="vertical" style={{ width: '100%' }}>
                <Input
                  readOnly
                  value={getOcspUrl()}
                  addonAfter={
                    <Button
                      type="text"
                      size="small"
                      icon={<CopyOutlined />}
                      onClick={handleCopyOcspUrl}
                    >
                      Copy URL
                    </Button>
                  }
                />
                <Alert
                  message="About OCSP"
                  description="OCSP (Online Certificate Status Protocol) provides real-time certificate status checking. This URL is automatically included in all newly generated certificates and is used by browsers and other clients to verify certificate validity."
                  type="info"
                  showIcon
                />
              </Space>
            </div>
          </Space>
        </Card>

        <Card>
          <Tabs
            items={[
              {
                key: 'windows',
                label: 'Windows',
                children: (
                  <div style={{ padding: 12 }}>
                    <Title level={5}>Installing CA Certificate on Windows</Title>
                    <ol>
                      <li>Download the CA certificate (PEM format)</li>
                      <li>Right-click the downloaded file and select "Install Certificate"</li>
                      <li>Choose "Local Machine" and click "Next"</li>
                      <li>Select "Place all certificates in the following store"</li>
                      <li>Click "Browse" and select "Trusted Root Certification Authorities"</li>
                      <li>Click "Next" and then "Finish"</li>
                    </ol>
                    <Alert
                      message="Administrator Rights Required"
                      description="Installing to Local Machine store requires administrator privileges"
                      type="warning"
                      showIcon
                    />
                  </div>
                ),
              },
              {
                key: 'macos',
                label: 'macOS',
                children: (
                  <div style={{ padding: 12 }}>
                    <Title level={5}>Installing CA Certificate on macOS</Title>
                    <ol>
                      <li>Download the CA certificate (PEM format)</li>
                      <li>Double-click the downloaded file</li>
                      <li>Keychain Access will open automatically</li>
                      <li>Select "System" keychain and click "Add"</li>
                      <li>Find the certificate in System keychain</li>
                      <li>Double-click it and expand "Trust"</li>
                      <li>Set "When using this certificate" to "Always Trust"</li>
                      <li>Close the window and enter your password</li>
                    </ol>
                  </div>
                ),
              },
              {
                key: 'linux',
                label: 'Linux',
                children: (
                  <div style={{ padding: 12 }}>
                    <Title level={5}>Installing CA Certificate on Linux</Title>
                    <Paragraph><strong>Ubuntu/Debian:</strong></Paragraph>
                    <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4 }}>
                      sudo cp ca-certificate.pem /usr/local/share/ca-certificates/trustcore.crt{'\n'}
                      sudo update-ca-certificates
                    </pre>
                    <Paragraph><strong>RHEL/CentOS/Fedora:</strong></Paragraph>
                    <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4 }}>
                      sudo cp ca-certificate.pem /etc/pki/ca-trust/source/anchors/{'\n'}
                      sudo update-ca-trust
                    </pre>
                  </div>
                ),
              },
              {
                key: 'ios',
                label: 'iOS',
                children: (
                  <div style={{ padding: 12 }}>
                    <Title level={5}>Installing CA Certificate on iOS</Title>
                    <ol>
                      <li>Email the CA certificate to yourself or host it on a web server</li>
                      <li>Open the certificate on your iOS device</li>
                      <li>Tap "Allow" to download the profile</li>
                      <li>Go to Settings → General → VPN & Device Management</li>
                      <li>Tap on the downloaded profile</li>
                      <li>Tap "Install" and enter your passcode</li>
                      <li>Tap "Install" again to confirm</li>
                      <li>Go to Settings → General → About → Certificate Trust Settings</li>
                      <li>Enable full trust for the certificate</li>
                    </ol>
                  </div>
                ),
              },
              {
                key: 'android',
                label: 'Android',
                children: (
                  <div style={{ padding: 12 }}>
                    <Title level={5}>Installing CA Certificate on Android</Title>
                    <ol>
                      <li>Download the CA certificate to your device</li>
                      <li>Go to Settings → Security → Encryption & credentials</li>
                      <li>Tap "Install a certificate"</li>
                      <li>Tap "CA certificate"</li>
                      <li>Tap "Install anyway" if warned</li>
                      <li>Browse to the downloaded certificate and select it</li>
                      <li>Enter a name for the certificate</li>
                      <li>Tap "OK"</li>
                    </ol>
                    <Alert
                      message="Security Warning"
                      description="Android will show a warning that network activity may be monitored. This is normal for CA installation."
                      type="info"
                      showIcon
                    />
                  </div>
                ),
              },
            ]}
          />
        </Card>

        {caCert && (
          <Card title="CA Certificate (PEM)">
            <div style={{ position: 'relative' }}>
              <Button
                size="small"
                icon={<CopyOutlined />}
                onClick={handleCopyCert}
                style={{ position: 'absolute', right: 8, top: 8, zIndex: 1 }}
              >
                Copy
              </Button>
              <pre style={{
                background: '#f5f5f5',
                padding: 16,
                borderRadius: 4,
                overflow: 'auto',
                fontSize: 12,
                fontFamily: 'JetBrains Mono, monospace'
              }}>
                {caCert}
              </pre>
            </div>
          </Card>
        )}
      </Space>
    </div>
  );
};