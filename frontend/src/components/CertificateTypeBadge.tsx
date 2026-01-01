import { Tag } from 'antd';
import { CertificateType } from '@/types';
import { getTypeColor } from '@/utils/helpers';
import { LaptopOutlined, UserOutlined, CloudServerOutlined } from '@ant-design/icons';

interface CertificateTypeBadgeProps {
  type: CertificateType;
}

const typeIcons: Record<CertificateType, React.ReactNode> = {
  machine: <LaptopOutlined />,
  user: <UserOutlined />,
  server: <CloudServerOutlined />,
};

export const CertificateTypeBadge: React.FC<CertificateTypeBadgeProps> = ({ type }) => {
  return (
    <Tag color={getTypeColor(type)} icon={typeIcons[type]}>
      {type}
    </Tag>
  );
};