import React, { useState, useEffect } from 'react';
import { Button, Card, Input, Table, Tag, message } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';

interface ApiKey {
  id: number;
  name: string;
  key: string;
  lastUsed: string;
  expiresAt: string;
  isActive: boolean;
}

const ApiKeyManager: React.FC = () => {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [expiresInDays, setExpiresInDays] = useState<number>(30);

  useEffect(() => {
    fetchApiKeys();
  }, []);

  const fetchApiKeys = async () => {
    try {
      const response = await fetch('/api/keys', {
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to fetch API keys');
      const data = await response.json();
      setApiKeys(data);
    } catch (error) {
      message.error('Failed to load API keys');
    }
  };

  const createApiKey = async () => {
    try {
      const response = await fetch('/api/keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          name: newKeyName,
          expiresInDays,
        }),
      });

      if (!response.ok) throw new Error('Failed to create API key');
      const data = await response.json();
      
      message.success('API key created successfully');
      message.info(`Your new API key: ${data.key} (Copy this now, it won't be shown again)`);
      
      setNewKeyName('');
      fetchApiKeys();
    } catch (error) {
      message.error('Failed to create API key');
    }
  };

  const deactivateApiKey = async (id: number) => {
    try {
      const response = await fetch(`/api/keys/${id}`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (!response.ok) throw new Error('Failed to deactivate API key');
      
      message.success('API key deactivated');
      fetchApiKeys();
    } catch (error) {
      message.error('Failed to deactivate API key');
    }
  };

  const columns = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: 'Status',
      dataIndex: 'isActive',
      key: 'isActive',
      render: (isActive: boolean) => (
        <Tag color={isActive ? 'green' : 'red'}>
          {isActive ? 'Active' : 'Inactive'}
        </Tag>
      ),
    },
    {
      title: 'Last Used',
      dataIndex: 'lastUsed',
      key: 'lastUsed',
      render: (date: string) => date ? new Date(date).toLocaleString() : 'Never',
    },
    {
      title: 'Expires',
      dataIndex: 'expiresAt',
      key: 'expiresAt',
      render: (date: string) => date ? new Date(date).toLocaleString() : 'Never',
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: any, record: ApiKey) => (
        <Button
          danger
          icon={<DeleteOutlined />}
          onClick={() => deactivateApiKey(record.id)}
          disabled={!record.isActive}
        >
          Deactivate
        </Button>
      ),
    },
  ];

  return (
    <Card title="API Key Management">
      <div style={{ marginBottom: 16 }}>
        <Input
          placeholder="Key Name"
          value={newKeyName}
          onChange={(e) => setNewKeyName(e.target.value)}
          style={{ width: 200, marginRight: 8 }}
        />
        <Input
          type="number"
          placeholder="Expires in days"
          value={expiresInDays}
          onChange={(e) => setExpiresInDays(Number(e.target.value))}
          style={{ width: 150, marginRight: 8 }}
        />
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={createApiKey}
          disabled={!newKeyName}
        >
          Create API Key
        </Button>
      </div>
      <Table
        columns={columns}
        dataSource={apiKeys}
        rowKey="id"
        pagination={false}
      />
    </Card>
  );
};

export default ApiKeyManager; 