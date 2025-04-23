export type SecurityEventType = 
  | 'LOGIN_ATTEMPT'
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILURE'
  | 'PASSWORD_RESET'
  | 'ACCOUNT_LOCKED'
  | 'SUSPICIOUS_ACTIVITY'
  | 'API_ACCESS'
  | 'FILE_ACCESS'
  | 'DATABASE_ACCESS';

export type SecurityEventSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SecurityEvent {
  id: string;
  eventType: SecurityEventType;
  ipAddress: string;
  userAgent: string;
  details: Record<string, any>;
  createdAt: Date;
  userId?: string | null;
  severity: SecurityEventSeverity;
} 