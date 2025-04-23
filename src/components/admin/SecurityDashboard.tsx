import React, { useState, useEffect } from 'react';
import { Card, Table, Tag, Statistic, Row, Col, DatePicker, Alert, Progress, Timeline, Select } from 'antd';
import { SecurityLogger } from '../../server/services/security-logger';
import { formatDistanceToNow, subDays } from 'date-fns';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const { RangePicker } = DatePicker;
const { Option } = Select;

interface SecurityEvent {
  id: string;
  eventType: string;
  ipAddress: string;
  userAgent: string;
  userId: string;
  details: any;
  createdAt: string;
}

interface SecurityStats {
  totalEvents: number;
  suspiciousActivity: number;
  failedLogins: number;
  recentEvents: SecurityEvent[];
  uniqueIPs: number;
  uniqueUsers: number;
  eventTrends: Array<{ date: string; count: number }>;
  threatLevel: 'low' | 'medium' | 'high';
  topThreats: Array<{ type: string; count: number }>;
  geoData: Array<{ country: string; count: number }>;
}

const SecurityDashboard: React.FC = () => {
  const [stats, setStats] = useState<SecurityStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dateRange, setDateRange] = useState<[Date, Date] | null>([
    subDays(new Date(), 7),
    new Date()
  ]);
  const [timeframe, setTimeframe] = useState<'hour' | 'day' | 'week'>('day');

  useEffect(() => {
    fetchSecurityStats();
  }, [dateRange, timeframe]);

  const fetchSecurityStats = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/security/stats', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          startDate: dateRange?.[0],
          endDate: dateRange?.[1],
          timeframe,
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch security stats');
      }
      
      const data = await response.json();
      setStats(data);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getEventTypeColor = (type: string) => {
    switch (type) {
      case 'LOGIN_SUCCESS':
        return 'success';
      case 'LOGIN_FAILED':
        return 'error';
      case 'SUSPICIOUS_ACTIVITY':
        return 'warning';
      case 'PASSWORD_RESET':
        return 'processing';
      default:
        return 'default';
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'low':
        return '#52c41a';
      case 'medium':
        return '#faad14';
      case 'high':
        return '#ff4d4f';
      default:
        return '#d9d9d9';
    }
  };

  const columns = [
    {
      title: 'Event Type',
      dataIndex: 'eventType',
      key: 'eventType',
      render: (type: string) => (
        <Tag color={getEventTypeColor(type)}>{type}</Tag>
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
        <pre style={{ maxWidth: 300, overflow: 'auto' }}>
          {JSON.stringify(details, null, 2)}
        </pre>
      ),
    },
    {
      title: 'Time',
      dataIndex: 'createdAt',
      key: 'createdAt',
      render: (date: string) => formatDistanceToNow(new Date(date), { addSuffix: true }),
    },
  ];

  return (
    <div style={{ padding: '24px' }}>
      <h1>Security Dashboard</h1>
      
      {error && (
        <Alert
          message="Error"
          description={error}
          type="error"
          showIcon
          style={{ marginBottom: 24 }}
        />
      )}

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="Total Events"
              value={stats?.totalEvents || 0}
              loading={loading}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Suspicious Activity"
              value={stats?.suspiciousActivity || 0}
              loading={loading}
              valueStyle={{ color: stats?.suspiciousActivity ? '#ff4d4f' : '#52c41a' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Failed Logins"
              value={stats?.failedLogins || 0}
              loading={loading}
              valueStyle={{ color: stats?.failedLogins ? '#ff4d4f' : '#52c41a' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Unique IPs"
              value={stats?.uniqueIPs || 0}
              loading={loading}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col span={12}>
          <Card title="Threat Level">
            <Progress
              percent={stats?.threatLevel === 'high' ? 100 : stats?.threatLevel === 'medium' ? 60 : 20}
              status={stats?.threatLevel === 'high' ? 'exception' : stats?.threatLevel === 'medium' ? 'active' : 'success'}
              strokeColor={getThreatLevelColor(stats?.threatLevel || 'low')}
            />
          </Card>
        </Col>
        <Col span={12}>
          <Card title="Top Threats">
            <Timeline>
              {stats?.topThreats.map((threat, index) => (
                <Timeline.Item key={index} color={getEventTypeColor(threat.type)}>
                  {threat.type}: {threat.count} events
                </Timeline.Item>
              ))}
            </Timeline>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col span={24}>
          <Card
            title="Event Trends"
            extra={
              <Select
                value={timeframe}
                onChange={setTimeframe}
                style={{ width: 120 }}
              >
                <Option value="hour">Hourly</Option>
                <Option value="day">Daily</Option>
                <Option value="week">Weekly</Option>
              </Select>
            }
          >
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={stats?.eventTrends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="count" stroke="#8884d8" />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      <Card
        title="Security Events"
        extra={
          <RangePicker
            onChange={(dates) => setDateRange(dates as [Date, Date])}
            showTime
          />
        }
      >
        <Table
          columns={columns}
          dataSource={stats?.recentEvents}
          loading={loading}
          rowKey="id"
          pagination={{ pageSize: 10 }}
        />
      </Card>
    </div>
  );
};

export default SecurityDashboard; 