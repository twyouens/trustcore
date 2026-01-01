import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, Descriptions, Space, Button, Tag, Typography, Alert, Modal, Form, Input, Radio, message } from 'antd';
import { 
  ArrowLeftOutlined, 
  DownloadOutlined, 
  CheckOutlined, 
  CloseOutlined,
  StopOutlined,
  CopyOutlined,
} from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { certificateService } from '@/services/certificate.service';
import { CertificateStatusBadge } from '@/components/CertificateStatusBadge';
import { CertificateTypeBadge } from '@/components/CertificateTypeBadge';
import { UserBadge } from '@/components/UserBadge';
import { DownloadCertificateModal } from '@/components/DownloadCertificateModal';
import { formatDate, copyToClipboard, getDefaultPassword } from '@/utils/helpers';
import { useAuthStore } from '@/store/authStore';

const { Title, Text } = Typography;

export const CertificateDetail = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuthStore();
  const isAdmin = user?.role === 'admin';

  const [downloadModalVisible, setDownloadModalVisible] = useState(false);
  const [approveModalVisible, setApproveModalVisible] = useState(false);
  const [revokeModalVisible, setRevokeModalVisible] = useState(false);
  const [approveForm] = Form.useForm();
  const [revokeForm] = Form.useForm();

  const { data: certificate, isLoading } = useQuery({
    queryKey: ['certificate', id],
    queryFn: () => certificateService.get(Number(id)),
    enabled: !!id,
  });

  const approveMutation = useMutation({
    mutationFn: (values: { approved: boolean; rejection_reason?: string }) =>
      certificateService.approve(Number(id), values),
    onSuccess: () => {
      message.success('Certificate updated successfully');
      queryClient.invalidateQueries({ queryKey: ['certificate', id] });
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
      setApproveModalVisible(false);
      approveForm.resetFields();
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (values: { reason: string }) =>
      certificateService.revoke(Number(id), values),
    onSuccess: () => {
      message.success('Certificate revoked successfully');
      queryClient.invalidateQueries({ queryKey: ['certificate', id] });
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
      setRevokeModalVisible(false);
      revokeForm.resetFields();
    },
  });

  const handleCopy = async (text: string) => {
    const success = await copyToClipboard(text);
    if (success) {
      message.success('Copied to clipboard');
    } else {
      message.error('Failed to copy');
    }
  };

  if (isLoading) {
    return <Card loading />;
  }

  if (!certificate) {
    return (
      <Card>
        <Alert
          message="Certificate Not Found"
          description="The requested certificate could not be found."
          type="error"
          showIcon
        />
      </Card>
    );
  }

  const canApprove = isAdmin && certificate.status === 'pending';
  const canRevoke = isAdmin && certificate.status === 'approved';
  const canDownload = certificate.status === 'approved' && certificate.certificate;

  const defaultPassword = getDefaultPassword(
    certificate.certificate_type,
    certificate.certificate_type === 'machine' ? certificate.common_name : certificate.common_name
  );

  return (
    <div>
      <Button 
        icon={<ArrowLeftOutlined />} 
        onClick={() => navigate('/certificates')}
        style={{ marginBottom: 16 }}
      >
        Back to Certificates
      </Button>

      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 24 }}>
            <div>
              <Title level={3} style={{ marginBottom: 8 }}>{certificate.common_name}</Title>
              <Space>
                <CertificateTypeBadge type={certificate.certificate_type} />
                <CertificateStatusBadge status={certificate.status} />
                {certificate.auto_approved && <Tag color="blue">Auto-Approved</Tag>}
              </Space>
            </div>
            
            <Space>
              {canDownload && (
                <Button 
                  type="primary" 
                  icon={<DownloadOutlined />}
                  onClick={() => setDownloadModalVisible(true)}
                >
                  Download
                </Button>
              )}
              {canApprove && (
                <>
                  <Button 
                    type="primary" 
                    icon={<CheckOutlined />}
                    onClick={() => {
                      approveForm.setFieldsValue({ approved: true });
                      setApproveModalVisible(true);
                    }}
                  >
                    Approve
                  </Button>
                  <Button 
                    danger
                    icon={<CloseOutlined />}
                    onClick={() => {
                      approveForm.setFieldsValue({ approved: false });
                      setApproveModalVisible(true);
                    }}
                  >
                    Reject
                  </Button>
                </>
              )}
              {canRevoke && (
                <Button 
                  danger
                  icon={<StopOutlined />}
                  onClick={() => setRevokeModalVisible(true)}
                >
                  Revoke
                </Button>
              )}
            </Space>
          </div>

          <Descriptions bordered column={2}>
            <Descriptions.Item label="Serial Number" span={2}>
              <Text code copyable>{certificate.serial_number}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Type">
              <CertificateTypeBadge type={certificate.certificate_type} />
            </Descriptions.Item>
            <Descriptions.Item label="Status">
              <CertificateStatusBadge status={certificate.status} />
            </Descriptions.Item>
            <Descriptions.Item label="Common Name" span={2}>
              {certificate.common_name}
            </Descriptions.Item>
            {certificate.subject_alternative_names && certificate.subject_alternative_names.length > 0 && (
              <Descriptions.Item label="Subject Alternative Names" span={2}>
                <Space wrap>
                  {certificate.subject_alternative_names.map((san, idx) => (
                    <Tag key={idx}>{san}</Tag>
                  ))}
                </Space>
              </Descriptions.Item>
            )}
            <Descriptions.Item label="Validity Days">
              {certificate.validity_days} days
            </Descriptions.Item>
            <Descriptions.Item label="Auto Approved">
              {certificate.auto_approved ? 'Yes' : 'No'}
            </Descriptions.Item>
            <Descriptions.Item label="Not Before">
              {certificate.not_before ? formatDate(certificate.not_before) : 'N/A'}
            </Descriptions.Item>
            <Descriptions.Item label="Not After">
              {certificate.not_after ? formatDate(certificate.not_after) : 'N/A'}
            </Descriptions.Item>
            <Descriptions.Item label="Created">
              {formatDate(certificate.created_at)}
            </Descriptions.Item>
            <Descriptions.Item label="Requested By">
              {certificate.requested_by_id && certificate.requested_by ? <UserBadge name={certificate.requested_by.full_name ?? 'N/A'} username={certificate.requested_by.username ?? 'N/A'} /> : 'N/A'}
            </Descriptions.Item>
            {certificate.approved_at && (
              <>
                <Descriptions.Item label={certificate.status === 'rejected' ? "Rejected At" : "Approved At"}>
                  {formatDate(certificate.approved_at)}
                </Descriptions.Item>
                <Descriptions.Item label={certificate.status === 'rejected' ? "Rejected By" : "Approved By"}>
                  {certificate.approved_by_id && certificate.approved_by ? <UserBadge name={certificate.approved_by.full_name ?? 'N/A'} username={certificate.approved_by.username ?? 'N/A'} /> : 'N/A'}
                </Descriptions.Item>
              </>
            )}
            {certificate.revoked_at && (
              <>
                <Descriptions.Item label="Revoked At">
                  {formatDate(certificate.revoked_at)}
                </Descriptions.Item>
                <Descriptions.Item label="Revoked By">
                  {certificate.revoked_by_id && certificate.revoked_by ? <UserBadge name={certificate.revoked_by.full_name ?? 'N/A'} username={certificate.revoked_by.username ?? 'N/A'} /> : 'N/A'}
                </Descriptions.Item>
                <Descriptions.Item label="Revocation Reason" span={2}>
                  {certificate.revocation_reason || 'N/A'}
                </Descriptions.Item>
              </>
            )}
            {certificate.status === 'rejected' && (
              <>
                <Descriptions.Item label="Rejection Reason" span={2}>
                  {certificate.revocation_reason || 'N/A'}
                </Descriptions.Item>
              </>
            )}
          </Descriptions>
        </Card>

        {certificate.csr && (
          <Card title="Certificate Signing Request (CSR)">
            <div style={{ position: 'relative' }}>
              <Button
                size="small"
                icon={<CopyOutlined />}
                onClick={() => handleCopy(certificate.csr!)}
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
                {certificate.csr}
              </pre>
            </div>
          </Card>
        )}

        {certificate.certificate && (
          <Card title="Certificate">
            <div style={{ position: 'relative' }}>
              <Button
                size="small"
                icon={<CopyOutlined />}
                onClick={() => handleCopy(certificate.certificate!)}
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
                {certificate.certificate}
              </pre>
            </div>
          </Card>
        )}
      </Space>

      <DownloadCertificateModal
        visible={downloadModalVisible}
        onCancel={() => setDownloadModalVisible(false)}
        certificateId={certificate.id}
        commonName={certificate.common_name}
        certificateType={certificate.certificate_type}
        defaultPassword={defaultPassword}
      />

      <Modal
        title="Approve/Reject Certificate"
        open={approveModalVisible}
        onOk={() => approveForm.submit()}
        onCancel={() => {
          setApproveModalVisible(false);
          approveForm.resetFields();
        }}
        confirmLoading={approveMutation.isPending}
      >
        <Form
          form={approveForm}
          layout="vertical"
          onFinish={(values) => approveMutation.mutate(values)}
        >
          <Form.Item name="approved" label="Action">
            <Radio.Group>
              <Radio value={true}>Approve</Radio>
              <Radio value={false}>Reject</Radio>
            </Radio.Group>
          </Form.Item>

          <Form.Item
            noStyle
            shouldUpdate={(prevValues, currentValues) => prevValues.approved !== currentValues.approved}
          >
            {({ getFieldValue }) =>
              getFieldValue('approved') === false && (
                <Form.Item
                  name="rejection_reason"
                  label="Rejection Reason"
                  rules={[{ required: true, message: 'Please provide a reason for rejection' }]}
                >
                  <Input.TextArea rows={4} placeholder="Explain why this certificate is being rejected..." />
                </Form.Item>
              )
            }
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="Revoke Certificate"
        open={revokeModalVisible}
        onOk={() => revokeForm.submit()}
        onCancel={() => {
          setRevokeModalVisible(false);
          revokeForm.resetFields();
        }}
        confirmLoading={revokeMutation.isPending}
        okText="Revoke"
        okButtonProps={{ danger: true }}
      >
        <Alert
          message="Warning"
          description="This action cannot be undone. The certificate will be added to the CRL."
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <Form
          form={revokeForm}
          layout="vertical"
          onFinish={(values) => revokeMutation.mutate(values)}
        >
          <Form.Item
            name="reason"
            label="Revocation Reason"
            rules={[{ required: true, message: 'Please provide a reason for revocation' }]}
          >
            <Input.TextArea rows={4} placeholder="Explain why this certificate is being revoked..." />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};