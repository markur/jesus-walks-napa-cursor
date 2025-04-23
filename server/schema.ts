import { pgTable, serial, text, timestamp, boolean, varchar, jsonb } from 'drizzle-orm/pg-core';

// Define security event types as a constant
export const SECURITY_EVENT_TYPES = {
  LOGIN_ATTEMPT: 'LOGIN_ATTEMPT',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  PASSWORD_RESET: 'PASSWORD_RESET',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
  API_ACCESS: 'API_ACCESS',
  FILE_ACCESS: 'FILE_ACCESS',
  DATABASE_ACCESS: 'DATABASE_ACCESS'
} as const;

// Define severity levels as a constant
export const SEVERITY_LEVELS = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
} as const;

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  username: varchar('username', { length: 255 }).notNull().unique(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  password: varchar('password', { length: 255 }).notNull(),
  failedLoginAttempts: serial('failed_login_attempts').default(0),
  lastFailedLogin: timestamp('last_failed_login'),
  twoFactorSecret: varchar('two_factor_secret', { length: 255 }),
  twoFactorEnabled: boolean('two_factor_enabled').default(false),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
  isAdmin: boolean('is_admin').default(false),
  isVerified: boolean('is_verified').default(false)
});

export const apiKeys = pgTable('api_keys', {
  id: serial('id').primaryKey(),
  userId: serial('user_id').references(() => users.id),
  key: varchar('key', { length: 64 }).notNull().unique(),
  name: varchar('name', { length: 255 }).notNull(),
  lastUsed: timestamp('last_used'),
  createdAt: timestamp('created_at').defaultNow(),
  expiresAt: timestamp('expires_at'),
  isActive: boolean('is_active').default(true)
});

export const securityEvents = pgTable('security_events', {
  id: serial('id').primaryKey(),
  userId: serial('user_id').references(() => users.id),
  eventType: varchar('event_type', { length: 50 }).notNull(),
  ipAddress: varchar('ip_address', { length: 45 }).notNull(),
  userAgent: varchar('user_agent', { length: 255 }),
  details: jsonb('details'),
  severity: varchar('severity', { length: 20 }).default('LOW'),
  createdAt: timestamp('created_at').defaultNow()
}); 