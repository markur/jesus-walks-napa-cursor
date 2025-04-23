import React, { useEffect, useRef, useState } from 'react';
import { message } from 'antd';
import { SecurityEvent } from '../types/security';

interface WebSocketMessage {
  type: string;
  data: SecurityEvent;
}

const SecurityWebSocket: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const ws = useRef<WebSocket | null>(null);
  const reconnectTimeout = useRef<NodeJS.Timeout>();

  const connect = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log('WebSocket connected');
      message.success('Connected to security events feed');
    };

    ws.current.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data);
        if (message.type === 'SECURITY_EVENT') {
          setEvents(prev => [message.data, ...prev].slice(0, 100));
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    ws.current.onclose = () => {
      console.log('WebSocket disconnected');
      message.warning('Disconnected from security events feed');
      // Attempt to reconnect after 5 seconds
      reconnectTimeout.current = setTimeout(connect, 5000);
    };

    ws.current.onerror = (error) => {
      console.error('WebSocket error:', error);
      message.error('Error connecting to security events feed');
    };
  };

  useEffect(() => {
    connect();

    return () => {
      if (ws.current) {
        ws.current.close();
      }
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
      }
    };
  }, []);

  return (
    <div>
      <h3>Real-time Security Events</h3>
      <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
        {events.map((event, index) => (
          <div key={index} style={{ marginBottom: '10px', padding: '10px', border: '1px solid #ddd' }}>
            <p><strong>Type:</strong> {event.eventType}</p>
            <p><strong>IP:</strong> {event.ipAddress}</p>
            <p><strong>Details:</strong> {event.details}</p>
            <p><strong>Time:</strong> {new Date(event.createdAt).toLocaleString()}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SecurityWebSocket; 