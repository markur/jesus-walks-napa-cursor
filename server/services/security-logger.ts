import { PrismaClient } from '@prisma/client';
import { Request } from 'express';

const prisma = new PrismaClient();

export interface SecurityEventDetails {
  [key: string]: any;
}

export class SecurityLogger {
  static async logEvent(
    eventType: string,
    request: Request,
    userId?: string,
    details?: SecurityEventDetails
  ) {
    try {
      const ipAddress = request.ip || request.connection.remoteAddress || '';
      const userAgent = request.headers['user-agent'] || '';

      // Add request details to the event
      const eventDetails = {
        ...details,
        method: request.method,
        path: request.path,
        query: request.query,
        headers: {
          'content-type': request.headers['content-type'],
          'origin': request.headers['origin'],
          'referer': request.headers['referer']
        }
      };

      // Create the security event
      await prisma.securityEvent.create({
        data: {
          eventType,
          ipAddress,
          userAgent,
          userId,
          details: eventDetails
        }
      });

      // Check for suspicious patterns
      if (ipAddress) {
        await this.checkForSuspiciousActivity(eventType, ipAddress, userId);
      }
    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  }

  private static async checkForSuspiciousActivity(
    eventType: string,
    ipAddress: string,
    userId?: string
  ) {
    try {
      // Check for multiple failed login attempts
      if (eventType === 'LOGIN_FAILED') {
        const recentFailedAttempts = await prisma.securityEvent.count({
          where: {
            eventType: 'LOGIN_FAILED',
            ipAddress,
            createdAt: {
              gte: new Date(Date.now() - 15 * 60 * 1000) // Last 15 minutes
            }
          }
        });

        if (recentFailedAttempts >= 5) {
          await this.logEvent('SUSPICIOUS_ACTIVITY', {} as Request, userId, {
            reason: 'Multiple failed login attempts',
            attempts: recentFailedAttempts
          });
        }
      }

      // Check for unusual IP changes
      if (userId && eventType === 'LOGIN_SUCCESS') {
        const recentLogins = await prisma.securityEvent.findMany({
          where: {
            userId,
            eventType: 'LOGIN_SUCCESS',
            createdAt: {
              gte: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
            }
          },
          select: {
            ipAddress: true
          }
        });

        const uniqueIPs = new Set(recentLogins.map(login => login.ipAddress));
        if (uniqueIPs.size > 3) {
          await this.logEvent('SUSPICIOUS_ACTIVITY', {} as Request, userId, {
            reason: 'Multiple IP addresses detected',
            ipAddresses: Array.from(uniqueIPs)
          });
        }
      }

      // Check for unusual activity patterns
      const recentEvents = await prisma.securityEvent.count({
        where: {
          ipAddress,
          createdAt: {
            gte: new Date(Date.now() - 60 * 60 * 1000) // Last hour
          }
        }
      });

      if (recentEvents > 100) {
        await this.logEvent('SUSPICIOUS_ACTIVITY', {} as Request, userId, {
          reason: 'High volume of requests',
          count: recentEvents
        });
      }
    } catch (error) {
      console.error('Failed to check for suspicious activity:', error);
    }
  }

  static async getSecurityReport(userId?: string) {
    try {
      const where = userId ? { userId } : {};

      const events = await prisma.securityEvent.findMany({
        where,
        orderBy: {
          createdAt: 'desc'
        },
        take: 100
      });

      const suspiciousActivity = await prisma.securityEvent.count({
        where: {
          ...where,
          eventType: 'SUSPICIOUS_ACTIVITY'
        }
      });

      const failedLogins = await prisma.securityEvent.count({
        where: {
          ...where,
          eventType: 'LOGIN_FAILED'
        }
      });

      return {
        totalEvents: events.length,
        suspiciousActivity,
        failedLogins,
        recentEvents: events
      };
    } catch (error) {
      console.error('Failed to generate security report:', error);
      throw error;
    }
  }
} 