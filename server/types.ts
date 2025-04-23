import { Session } from 'express-session';

export interface User {
  id: string;
  username: string;
  password: string;
  email: string;
  failedLoginAttempts: number;
  lastFailedLogin: Date | null;
  createdAt: Date;
  updatedAt: Date;
  isAdmin: boolean;
  isVerified: boolean;
  verificationToken?: string;
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
  twoFactorSecret?: string;
  twoFactorEnabled: boolean;
}

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    temp2FASecret?: string;
    isAuthenticated?: boolean;
    csrfToken?: string;
  }
}

export interface SecurityEvent {
  id: string;
  eventType: string;
  userId: string | null;
  ipAddress: string;
  userAgent: string;
  details?: Record<string, any>;
  createdAt: Date;
  severity?: 'low' | 'medium' | 'high' | 'critical';
} 