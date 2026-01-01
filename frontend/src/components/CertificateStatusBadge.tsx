import { Tag } from 'antd';
import { CertificateStatus } from '@/types';
import { getStatusColor } from '@/utils/helpers';
import {
  ClockCircleOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  StopOutlined,
} from '@ant-design/icons';

interface CertificateStatusBadgeProps {
  status: CertificateStatus;
}

const statusIcons: Record<CertificateStatus, React.ReactNode> = {
  pending: <ClockCircleOutlined />,
  approved: <CheckCircleOutlined />,
  rejected: <CloseCircleOutlined />,
  revoked: <StopOutlined />,
};

export const CertificateStatusBadge: React.FC<CertificateStatusBadgeProps> = ({ status }) => {
  return (
    <Tag color={getStatusColor(status)} icon={statusIcons[status]}>
      {status}
    </Tag>
  );
};