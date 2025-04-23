import { Server } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { SecurityEvent } from '../src/types/security';

const clients = new Set<WebSocket>();

export const setupWebSocketServer = (server: Server) => {
  const wss = new WebSocketServer({ server });

  wss.on('connection', (ws: WebSocket) => {
    clients.add(ws);

    ws.on('close', () => {
      clients.delete(ws);
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
      clients.delete(ws);
    });
  });

  return wss;
};

export const broadcastSecurityEvent = (event: SecurityEvent) => {
  const message = JSON.stringify({
    type: 'SECURITY_EVENT',
    data: event
  });

  clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}; 