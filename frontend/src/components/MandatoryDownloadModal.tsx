import { useState } from 'react';
import { Modal, Alert, Space, Typography, Button, Spin } from 'antd';
import { DownloadOutlined, WarningOutlined } from '@ant-design/icons';
import { downloadBlob, getFileExtension } from '@/utils/helpers';
import { message } from 'antd';
import { OutputFormat } from '@/types';

const { Title, Text, Paragraph } = Typography;

interface MandatoryDownloadModalProps {
  visible: boolean;
  certificateData: string; // Base64 or PEM string
  certificateType: 'machine' | 'user' | 'server';
  commonName: string;
  outputFormat: OutputFormat;
  onDownloadComplete: () => void; // Called only after successful download
}

export const MandatoryDownloadModal: React.FC<MandatoryDownloadModalProps> = ({
  visible,
  certificateData,
  certificateType,
  commonName,
  outputFormat,
  onDownloadComplete,
}) => {
  const [hasDownloaded, setHasDownloaded] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  const handleDownload = async () => {
    try {
      setIsDownloading(true);
      
      // Determine if data is base64 or PEM
      let blob: Blob;
      const extension = getFileExtension(outputFormat);
      
      if (outputFormat === 'pem') {
        // PEM format is plain text
        blob = new Blob([certificateData], { type: 'text/plain' });
      } else {
        // PKCS12 and DER are base64 encoded
        // Convert base64 to binary
        const binaryString = atob(certificateData);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        blob = new Blob([bytes], { type: 'application/octet-stream' });
      }

      // Generate filename
      const sanitizedName = commonName.replace(/[^a-zA-Z0-9]/g, '_');
      const filename = `${sanitizedName}.${extension}`;
      
      // Download
      downloadBlob(blob, filename);
      
      setHasDownloaded(true);
      message.success('Certificate downloaded successfully');
      
    } catch (error) {
      console.error('Download error:', error);
      message.error('Failed to download certificate. Please try again.');
    } finally {
      setIsDownloading(false);
    }
  };

  const handleClose = () => {
    if (hasDownloaded) {
      onDownloadComplete();
    } else {
      message.warning('Please download the certificate before closing');
    }
  };

  const formatName = outputFormat === 'pkcs12' ? 'PKCS12 (.p12)' : 
                     outputFormat === 'der' ? 'DER (.der)' : 'PEM (.pem)';

  return (
    <Modal
      title={
        <Space>
          <WarningOutlined style={{ color: '#faad14' }} />
          <span>Download Your Certificate</span>
        </Space>
      }
      open={visible}
      closable={hasDownloaded}
      maskClosable={false}
      keyboard={false}
      footer={
        <Space>
          <Button
            type="primary"
            size="large"
            icon={<DownloadOutlined />}
            onClick={handleDownload}
            loading={isDownloading}
          >
            {hasDownloaded ? 'Re-download Certificate' : 'Download Certificate'}
          </Button>
          {hasDownloaded && (
            <Button size="large" onClick={handleClose}>
              Continue
            </Button>
          )}
        </Space>
      }
      width={600}
    >
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <Alert
          message="⚠️ Important: One-Time Download"
          description={
            <div>
              <Paragraph style={{ marginBottom: 8 }}>
                This certificate <strong>includes your private key</strong> and can only be downloaded once.
                The private key cannot be retrieved later for security reasons.
              </Paragraph>
              <Paragraph style={{ marginBottom: 0 }}>
                <strong>You must download it now before closing this window.</strong>
              </Paragraph>
            </div>
          }
          type="warning"
          showIcon
        />

        <div>
          <Title level={5}>Certificate Information</Title>
          <Space direction="vertical" size={0} style={{ width: '100%' }}>
            <Text><strong>Type:</strong> {certificateType}</Text>
            <Text><strong>Common Name:</strong> {commonName}</Text>
            <Text><strong>Format:</strong> {formatName}</Text>
          </Space>
        </div>

        {outputFormat === 'pkcs12' && (
          <Alert
            message="PKCS12 Format"
            description="This file includes both your certificate and private key in a password-protected bundle. Keep the password safe as you'll need it during installation."
            type="info"
            showIcon
          />
        )}

        {!hasDownloaded && (
          <Alert
            message="Next Steps After Download"
            description={
              <ol style={{ marginBottom: 0, paddingLeft: 20 }}>
                <li>Click the "Download Certificate" button above</li>
                <li>Save the file to a secure location</li>
                <li>Back up the file to prevent loss</li>
                <li>Install the certificate on your device</li>
              </ol>
            }
            type="info"
          />
        )}

        {hasDownloaded && (
          <Alert
            message="✅ Certificate Downloaded Successfully"
            description="You can now close this window and proceed to view the certificate details or install it on your device."
            type="success"
            showIcon
          />
        )}

        {isDownloading && (
          <div style={{ textAlign: 'center', padding: '20px 0' }}>
            <Spin size="large" />
            <div style={{ marginTop: 16 }}>
              <Text type="secondary">Preparing download...</Text>
            </div>
          </div>
        )}
      </Space>
    </Modal>
  );
};