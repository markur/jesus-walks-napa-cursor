import React, { useState, useEffect } from 'react';
import { Card, Table, Tag, message } from 'antd';

interface SecurityEvent {
  id: number;
  eventType: string;
  ipAddress: string;
  userAgent: string;
  details: any;
  createdAt: string;
}

const SecurityEvents: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);

  useEffect(() => {
    fetchSecurityEvents();
  }, []);

  const fetchSecurityEvents = async () => {
    try {
      const response = await fetch('/api/security/events', {
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to fetch security events');
      const data = await response.json();
      setEvents(data);
    } catch (error) {
      message.error('Failed to load security events');
    }
  };

  const getEventTypeColor = (type: string) => {
    switch (type) {
      case 'api_key_created':
        return 'green';
      case 'api_key_deactivated':
        return 'orange';
      case 'api_key_invalid':
      case 'api_key_expired':
        return 'red';
      case 'login_success':
        return 'green';
      case 'login_failed':
        return 'red';
      default:
        return 'blue';
    }
  };

  const columns = [
    {
      title: 'Event Type',
      dataIndex: 'eventType',
      key: 'eventType',
      render: (type: string) => (
        <Tag color={getEventTypeColor(type)}>
          {type.replace(/_/g, ' ').toUpperCase()}
        </Tag>
      ),
    },
    {
      title: 'IP Address',
      dataIndex: 'ipAddress',
      key: 'ipAddress',
    },
    {
      title: 'User Agent',
      dataIndex: 'userAgent',
      key: 'userAgent',
      ellipsis: true,
    },
    {
      title: 'Details',
      dataIndex: 'details',
      key: 'details',
      render: (details: any) => (
        <pre style={{ margin: 0 }}>
          {JSON.stringify(details, null, 2)}
        </pre>
      ),
    },
    {
      title: 'Timestamp',
      dataIndex: 'createdAt',
      key: 'createdAt',
      render: (date: string) => new Date(date).toLocaleString(),
    },
  ];

  return (
    <Card title="Security Events">
      <Table
        columns={columns}
        dataSource={events}
        rowKey="id"
        pagination={{ pageSize: 10 }}
      />
    </Card>
  );
};

export default SecurityEvents; 