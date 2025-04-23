import { Session, SessionData } from 'express-session';

declare module 'express-session' {
  interface SessionData {
    userId?: number;
    temp2FASecret?: string;
    failedLoginAttempts?: number;
    lastFailedLogin?: Date;
    two_factor_enabled?: boolean;
  }
}

declare module 'express' {
  interface Request {
    session: Session & SessionData;
  }
} 