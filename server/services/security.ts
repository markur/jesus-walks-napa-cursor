import { PrismaClient } from '@prisma/client';
import { WebSocket } from 'ws';
import nodemailer from 'nodemailer';
import { SecurityEvent, SecurityEventType, SecurityEventSeverity } from '../../src/types/security';
import { broadcastSecurityEvent } from '../websocket';

const prisma = new PrismaClient();

interface SecurityEventInput extends Omit<SecurityEvent, 'id' | 'createdAt'> {
  severity?: SecurityEventSeverity;
}

export class SecurityService {
  private static instance: SecurityService;
  private wsClients: Set<WebSocket> = new Set();
  private alertThresholds = {
    suspiciousActivity: 5,
    failedLogins: 10,
    uniqueIPs: 100,
    suspiciousIPs: 3
  };

  private constructor() {}

  public static getInstance(): SecurityService {
    if (!SecurityService.instance) {
      SecurityService.instance = new SecurityService();
    }
    return SecurityService.instance;
  }

  public addWebSocketClient(ws: WebSocket) {
    this.wsClients.add(ws);
    ws.on('close', () => this.wsClients.delete(ws));
  }

  public async logSecurityEvent(event: SecurityEventInput): Promise<void> {
    try {
      const securityEvent = await prisma.securityEvent.create({
        data: {
          eventType: event.eventType as SecurityEventType,
          ipAddress: event.ipAddress,
          userAgent: event.userAgent || '',
          details: event.details || {},
          userId: event.userId,
          severity: event.severity || 'LOW'
        }
      });

      // Broadcast the event to connected WebSocket clients
      broadcastSecurityEvent({
        ...event,
        id: securityEvent.id,
        createdAt: securityEvent.createdAt
      });
    } catch (error) {
      console.error('Error logging security event:', error);
      throw error;
    }
  }

  public async getSecurityEvents(
    limit: number = 100,
    offset: number = 0
  ): Promise<SecurityEvent[]> {
    try {
      const events = await prisma.securityEvent.findMany({
        take: limit,
        skip: offset,
        orderBy: {
          createdAt: 'desc'
        }
      });

      return events.map(event => ({
        id: event.id,
        eventType: event.eventType as SecurityEventType,
        userId: event.userId,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent || '',
        details: event.details || {},
        createdAt: event.createdAt,
        severity: event.severity as SecurityEventSeverity
      }));
    } catch (error) {
      console.error('Error fetching security events:', error);
      throw error;
    }
  }

  private async checkForThreats(event: SecurityEvent) {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    // Check for suspicious activity from the same IP
    const suspiciousActivity = await prisma.securityEvent.count({
      where: {
        ipAddress: event.ipAddress,
        eventType: 'SUSPICIOUS_ACTIVITY',
        createdAt: {
          gte: oneHourAgo
        }
      }
    });

    if (suspiciousActivity >= this.alertThresholds.suspiciousActivity) {
      await this.sendAlert('Suspicious Activity Alert', {
        ipAddress: event.ipAddress,
        eventCount: suspiciousActivity,
        lastEvent: event
      });
    }

    // Check for failed login attempts
    const failedLogins = await prisma.securityEvent.count({
      where: {
        ipAddress: event.ipAddress,
        eventType: 'LOGIN_FAILURE',
        createdAt: {
          gte: oneHourAgo
        }
      }
    });

    if (failedLogins >= this.alertThresholds.failedLogins) {
      await this.sendAlert('Failed Login Attempts Alert', {
        ipAddress: event.ipAddress,
        attemptCount: failedLogins,
        lastEvent: event
      });
    }

    // Check for unique IPs in the last hour
    const uniqueIPs = await prisma.securityEvent.count({
      where: {
        createdAt: {
          gte: oneHourAgo
        }
      },
      distinct: ['ipAddress']
    });

    if (uniqueIPs >= this.alertThresholds.uniqueIPs) {
      await this.sendAlert('High Volume of Unique IPs', {
        uniqueIPCount: uniqueIPs,
        lastEvent: event
      });
    }

    // Check for suspicious IPs
    const suspiciousIPs = await prisma.securityEvent.count({
      where: {
        eventType: 'SUSPICIOUS_ACTIVITY',
        createdAt: {
          gte: oneHourAgo
        }
      },
      distinct: ['ipAddress']
    });

    if (suspiciousIPs >= this.alertThresholds.suspiciousIPs) {
      await this.sendAlert('Multiple Suspicious IPs Detected', {
        suspiciousIPCount: suspiciousIPs,
        lastEvent: event
      });
    }
  }

  private async sendAlert(subject: string, data: any) {
    if (!process.env.SMTP_HOST || !process.env.SMTP_PORT || !process.env.SMTP_USER || !process.env.SMTP_PASSWORD || !process.env.SMTP_FROM) {
      console.error('SMTP configuration is missing');
      return;
    }

    // Send email alert
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT),
      secure: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
      },
    });

    const adminEmails = await prisma.user.findMany({
      where: {
        role: 'ADMIN',
      },
      select: {
        email: true,
      },
    });

    const mailOptions = {
      from: process.env.SMTP_FROM,
      to: adminEmails.map(admin => admin.email).join(', '),
      subject: `Security Alert: ${subject}`,
      html: `
        <h1>Security Alert</h1>
        <h2>${subject}</h2>
        <pre>${JSON.stringify(data, null, 2)}</pre>
      `,
    };

    try {
      await transporter.sendMail(mailOptions);
    } catch (error) {
      console.error('Error sending security alert email:', error);
    }
  }

  private broadcastEvent(event: SecurityEvent) {
    this.wsClients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(event));
      }
    });
  }

  private broadcastAlert(alert: any) {
    this.wsClients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: 'alert', data: alert }));
      }
    });
  }
} 