import { useState } from 'react';
import { Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Radio, message, Alert } from 'antd';
import { CheckOutlined, CloseOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { certificateService } from '@/services/certificate.service';
import { useNavigate } from 'react-router-dom';
import { CertificateTypeBadge } from '@/components/CertificateTypeBadge';
import { formatDate } from '@/utils/helpers';
import { Certificate } from '@/types';
import type { ColumnsType } from 'antd/es/table';

const { Title, Text } = Typography;

export const PendingApprovals = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [selectedCert, setSelectedCert] = useState<Certificate | null>(null);
  const [modalVisible, setModalVisible] = useState(false);
  const [form] = Form.useForm();
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['certificates', 'pending'],
    queryFn: () => certificateService.list({ status: 'pending', limit: 100 }),
  });

  const approveMutation = useMutation({
    mutationFn: ({ id, values }: { id: number; values: any }) =>
      certificateService.approve(id, values),
    onSuccess: () => {
      message.success('Certificate updated successfully');
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
      setModalVisible(false);
      setSelectedCert(null);
      form.resetFields();
    },
  });

  const handleAction = (cert: Certificate, approved: boolean) => {
    setSelectedCert(cert);
    form.setFieldsValue({ approved });
    setModalVisible(true);
  };

  const handleSubmit = (values: any) => {
    if (selectedCert) {
      approveMutation.mutate({ id: selectedCert.id, values });
    }
  };

  const handleBulkApprove = () => {
    Modal.confirm({
      title: 'Bulk Approve Certificates',
      content: `Are you sure you want to approve ${selectedRowKeys.length} certificate(s)?`,
      onOk: async () => {
        for (const id of selectedRowKeys) {
          await certificateService.approve(Number(id), { approved: true });
        }
        message.success(`Approved ${selectedRowKeys.length} certificate(s)`);
        queryClient.invalidateQueries({ queryKey: ['certificates'] });
        setSelectedRowKeys([]);
      },
    });
  };

  const columns: ColumnsType<Certificate> = [
    {
      title: 'Type',
      dataIndex: 'certificate_type',
      key: 'type',
      width: 120,
      render: (type) => <CertificateTypeBadge type={type} />,
    },
    {
      title: 'Common Name',
      dataIndex: 'common_name',
      key: 'common_name',
      ellipsis: true,
      render: (name, record) => (
        <Space direction="vertical" size={0}>
          <a onClick={() => navigate(`/certificates/${record.id}`)}>{name}</a>
          {record.subject_alternative_names && record.subject_alternative_names.length > 0 && (
            <Text type="secondary" style={{ fontSize: 12 }}>
              SANs: {record.subject_alternative_names.slice(0, 2).join(', ')}
              {record.subject_alternative_names.length > 2 && ` +${record.subject_alternative_names.length - 2}`}
            </Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Requested By',
      dataIndex: 'requested_by_id',
      key: 'requested_by',
      width: 120,
      render: (id) => `User ${id}`,
    },
    {
      title: 'Requested Date',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date) => formatDate(date),
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    },
    {
      title: 'Validity',
      dataIndex: 'validity_days',
      key: 'validity',
      width: 100,
      render: (days) => `${days} days`,
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 180,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button
            type="primary"
            size="small"
            icon={<CheckOutlined />}
            onClick={() => handleAction(record, true)}
          >
            Approve
          </Button>
          <Button
            danger
            size="small"
            icon={<CloseOutlined />}
            onClick={() => handleAction(record, false)}
          >
            Reject
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>Pending Approvals</Title>
        <Text type="secondary">
          Review and approve certificate requests from users
        </Text>
      </div>

      <Card>
        {data?.total === 0 ? (
          <Alert
            message="No Pending Approvals"
            description="All certificate requests have been reviewed. New requests will appear here."
            type="success"
            showIcon
          />
        ) : (
          <>
            <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }}>
              <Space>
                {selectedRowKeys.length > 0 && (
                  <Button
                    type="primary"
                    icon={<CheckOutlined />}
                    onClick={handleBulkApprove}
                  >
                    Approve Selected ({selectedRowKeys.length})
                  </Button>
                )}
                <Tag color="warning">
                  {data?.total || 0} Pending Request{(data?.total || 0) !== 1 ? 's' : ''}
                </Tag>
              </Space>
              <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
                Refresh
              </Button>
            </Space>

            <Table
              dataSource={data?.items}
              columns={columns}
              rowKey="id"
              loading={isLoading}
              pagination={{
                pageSize: 10,
                showSizeChanger: true,
                showTotal: (total) => `Total ${total} pending`,
              }}
              rowSelection={{
                selectedRowKeys,
                onChange: setSelectedRowKeys,
              }}
              scroll={{ x: 1200 }}
            />
          </>
        )}
      </Card>

      <Modal
        title={`${form.getFieldValue('approved') ? 'Approve' : 'Reject'} Certificate`}
        open={modalVisible}
        onOk={() => form.submit()}
        onCancel={() => {
          setModalVisible(false);
          setSelectedCert(null);
          form.resetFields();
        }}
        confirmLoading={approveMutation.isPending}
      >
        {selectedCert && (
          <>
            <Alert
              message="Certificate Details"
              description={
                <Space direction="vertical" size={0}>
                  <Text><strong>Type:</strong> {selectedCert.certificate_type}</Text>
                  <Text><strong>Common Name:</strong> {selectedCert.common_name}</Text>
                  <Text><strong>Validity:</strong> {selectedCert.validity_days} days</Text>
                  <Text><strong>Requested:</strong> {formatDate(selectedCert.created_at)}</Text>
                </Space>
              }
              type="info"
              style={{ marginBottom: 16 }}
            />

            <Form form={form} layout="vertical" onFinish={handleSubmit}>
              <Form.Item name="approved" label="Action">
                <Radio.Group>
                  <Radio value={true}>Approve</Radio>
                  <Radio value={false}>Reject</Radio>
                </Radio.Group>
              </Form.Item>

              <Form.Item
                noStyle
                shouldUpdate={(prevValues, currentValues) =>
                  prevValues.approved !== currentValues.approved
                }
              >
                {({ getFieldValue }) =>
                  getFieldValue('approved') === false && (
                    <Form.Item
                      name="rejection_reason"
                      label="Rejection Reason"
                      rules={[
                        { required: true, message: 'Please provide a reason for rejection' },
                      ]}
                    >
                      <Input.TextArea
                        rows={4}
                        placeholder="Explain why this certificate is being rejected..."
                      />
                    </Form.Item>
                  )
                }
              </Form.Item>
            </Form>
          </>
        )}
      </Modal>
    </div>
  );
};