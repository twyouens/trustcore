import React from 'react';
import { Tag, Tooltip } from 'antd';
import { UserOutlined } from '@ant-design/icons';

interface UserBadgeProps {
    name: string;
    username: string;
}

/**
 * UserBadge
 * - displays the user's name
 * - shows the user's username on hover via antd Tooltip
 */
export const UserBadge: React.FC<UserBadgeProps> = ({ name, username }) => {
    const tooltipTitle = username;

    return (
        <Tooltip title={tooltipTitle}>
            <Tag color={'green-inverse'} icon={<UserOutlined />}>
                {name}
            </Tag>
        </Tooltip>
    );
};