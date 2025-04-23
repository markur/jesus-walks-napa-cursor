import { users, events, registrations, waitlist, products, orders, orderItems, modelConfigs, conversations, messages } from "@shared/schema";
import type { User, Event, Registration, Waitlist, Product, Order, OrderItem, InsertUser, InsertEvent, InsertRegistration, InsertWaitlist, InsertProduct, InsertOrder, InsertOrderItem, ModelConfig, InsertModelConfig, Conversation, InsertConversation, Message, InsertMessage } from "@shared/schema";
import { db } from "./db";
import { eq } from "drizzle-orm";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { pool as dbPool } from "./db";
import { Pool } from 'pg';
import { z } from 'zod';
import { SecurityEvent, SecurityEventType, SecurityEventSeverity } from '../src/types/security';

// Database connection pool configuration
const storagePool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000, // How long a client is allowed to remain idle before being closed
  connectionTimeoutMillis: 2000, // How long to wait for a connection
  ssl: {
    rejectUnauthorized: false // Required for some cloud providers
  }
});

// Prepared statements
const preparedStatements = {
  getUserById: 'SELECT * FROM users WHERE id = $1',
  getUserByUsername: 'SELECT * FROM users WHERE username = $1',
  getUserByEmail: 'SELECT * FROM users WHERE email = $1',
  createUser: 'INSERT INTO users (username, email, password, failed_login_attempts, last_failed_login) VALUES ($1, $2, $3, $4, $5) RETURNING *',
  updateFailedLoginAttempts: 'UPDATE users SET failed_login_attempts = $1, last_failed_login = $2 WHERE id = $3',
  resetFailedLoginAttempts: 'UPDATE users SET failed_login_attempts = 0 WHERE id = $1',
  enable2FA: 'UPDATE users SET two_factor_secret = $1, two_factor_enabled = true WHERE id = $2',
  disable2FA: 'UPDATE users SET two_factor_secret = NULL, two_factor_enabled = false WHERE id = $1',
  verify2FA: 'SELECT two_factor_secret FROM users WHERE id = $1',
  
  // API Key statements
  createApiKey: 'INSERT INTO api_keys (user_id, key, name, expires_at) VALUES ($1, $2, $3, $4) RETURNING *',
  getApiKey: 'SELECT * FROM api_keys WHERE key = $1 AND is_active = true',
  getUserApiKeys: 'SELECT * FROM api_keys WHERE user_id = $1',
  deactivateApiKey: 'UPDATE api_keys SET is_active = false WHERE id = $1 AND user_id = $2',
  updateApiKeyLastUsed: 'UPDATE api_keys SET last_used = NOW() WHERE id = $1',
  
  // Security Event statements
  logSecurityEvent: 'INSERT INTO security_events (user_id, event_type, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)',
  getSecurityEvents: 'SELECT * FROM security_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2'
};

// Error handling for database operations
const handleDatabaseError = (error: Error) => {
  console.error('Database error:', error);
  throw new Error('Database operation failed');
};

export interface IStorage {
  // User operations
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;

  // Event operations
  getEvent(id: number): Promise<Event | undefined>;
  getAllEvents(): Promise<Event[]>;
  createEvent(event: InsertEvent): Promise<Event>;

  // Registration operations
  getRegistration(id: number): Promise<Registration | undefined>;
  createRegistration(registration: InsertRegistration): Promise<Registration>;
  getEventRegistrations(eventId: number): Promise<Registration[]>;

  // Waitlist operations
  addToWaitlist(email: InsertWaitlist): Promise<Waitlist>;
  isEmailInWaitlist(email: string): Promise<boolean>;

  // Product operations
  getProduct(id: number): Promise<Product | undefined>;
  getAllProducts(): Promise<Product[]>;
  getProductsByCategory(category: string): Promise<Product[]>;
  createProduct(product: InsertProduct): Promise<Product>;
  updateProductStock(id: number, quantity: number): Promise<Product>;

  // Order operations
  getOrder(id: number): Promise<Order | undefined>;
  getUserOrders(userId: number): Promise<Order[]>;
  createOrder(order: InsertOrder): Promise<Order>;
  updateOrderStatus(id: number, status: string): Promise<Order>;

  // Order Item operations
  getOrderItems(orderId: number): Promise<OrderItem[]>;
  createOrderItem(orderItem: InsertOrderItem): Promise<OrderItem>;

  // Admin operations
  getAllUsers(): Promise<User[]>;
  getAllOrders(): Promise<Order[]>;
  updateUserRole(userId: number, isAdmin: boolean): Promise<User>;

  // Session store
  sessionStore: session.Store;

  // Model config operations
  getModelConfig(id: number): Promise<ModelConfig | undefined>;
  getAllModelConfigs(): Promise<ModelConfig[]>;
  createModelConfig(config: InsertModelConfig): Promise<ModelConfig>;
  getActiveModelConfigs(): Promise<ModelConfig[]>;

  // Conversation operations
  getConversation(id: number): Promise<Conversation | undefined>;
  getUserConversations(userId: number): Promise<Conversation[]>;
  createConversation(conversation: InsertConversation): Promise<Conversation>;

  // Message operations
  getConversationMessages(conversationId: number): Promise<Message[]>;
  createMessage(message: InsertMessage): Promise<Message>;

  // 2FA operations
  enable2FA(userId: number, secret: string): Promise<void>;
  disable2FA(userId: number): Promise<void>;
  get2FASecret(userId: number): Promise<string | null>;

  // API Key operations
  createApiKey(userId: number, key: string, name: string, expiresAt?: Date): Promise<any>;
  getApiKey(key: string): Promise<any>;
  getUserApiKeys(userId: number): Promise<any[]>;
  deactivateApiKey(keyId: number, userId: number): Promise<void>;
  updateApiKeyLastUsed(keyId: number): Promise<void>;
  
  // Security Event operations
  logSecurityEvent(userId: number, eventType: string, ipAddress: string, userAgent: string, details: any): Promise<void>;
  getSecurityEvents(userId: number, limit: number): Promise<any[]>;

  // New security event operations
  createSecurityEvent(event: Omit<SecurityEvent, 'id'>): Promise<SecurityEvent>;
}

export class DatabaseStorage implements IStorage {
  sessionStore: session.Store;
  private pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
    const PostgresStore = connectPgSimple(session);
    this.sessionStore = new PostgresStore({
      pool,
      createTableIfMissing: true,
    });
  }

  async getUser(id: number): Promise<User | undefined> {
    try {
      const result = await this.pool.query(preparedStatements.getUserById, [id]);
      return result.rows[0];
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    try {
      const result = await this.pool.query(preparedStatements.getUserByUsername, [username]);
      return result.rows[0];
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    try {
      const result = await this.pool.query(preparedStatements.getUserByEmail, [email]);
      return result.rows[0];
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async createUser(user: InsertUser): Promise<User> {
    try {
      const result = await this.pool.query<User>(preparedStatements.createUser, [
        user.username,
        user.password,
        user.email,
        user.failedLoginAttempts || 0,
        user.lastFailedLogin || null
      ]);
      return result.rows[0];
    } catch (error) {
      handleDatabaseError(error as Error);
      throw error;
    }
  }

  async getEvent(id: number): Promise<Event | undefined> {
    const [event] = await db.select().from(events).where(eq(events.id, id));
    return event;
  }

  async getAllEvents(): Promise<Event[]> {
    return await db.select().from(events);
  }

  async createEvent(event: InsertEvent): Promise<Event> {
    const [newEvent] = await db.insert(events).values(event).returning();
    return newEvent;
  }

  async getRegistration(id: number): Promise<Registration | undefined> {
    const [registration] = await db.select().from(registrations).where(eq(registrations.id, id));
    return registration;
  }

  async createRegistration(registration: InsertRegistration): Promise<Registration> {
    const [newRegistration] = await db.insert(registrations).values(registration).returning();
    return newRegistration;
  }

  async getEventRegistrations(eventId: number): Promise<Registration[]> {
    return await db.select().from(registrations).where(eq(registrations.eventId, eventId));
  }

  async addToWaitlist(email: InsertWaitlist): Promise<Waitlist> {
    const [entry] = await db.insert(waitlist).values(email).returning();
    return entry;
  }

  async isEmailInWaitlist(email: string): Promise<boolean> {
    const [entry] = await db.select().from(waitlist).where(eq(waitlist.email, email));
    return !!entry;
  }

  async getProduct(id: number): Promise<Product | undefined> {
    const [product] = await db.select().from(products).where(eq(products.id, id));
    return product;
  }

  async getAllProducts(): Promise<Product[]> {
    return await db.select().from(products);
  }

  async getProductsByCategory(category: string): Promise<Product[]> {
    return await db.select().from(products).where(eq(products.category, category));
  }

  async createProduct(product: InsertProduct): Promise<Product> {
    const [newProduct] = await db.insert(products).values(product).returning();
    return newProduct;
  }

  async updateProductStock(id: number, quantity: number): Promise<Product> {
    const [updatedProduct] = await db
      .update(products)
      .set({ stock: quantity })
      .where(eq(products.id, id))
      .returning();
    return updatedProduct;
  }

  async getOrder(id: number): Promise<Order | undefined> {
    const [order] = await db.select().from(orders).where(eq(orders.id, id));
    return order;
  }

  async getUserOrders(userId: number): Promise<Order[]> {
    return await db.select().from(orders).where(eq(orders.userId, userId));
  }

  async createOrder(order: InsertOrder): Promise<Order> {
    const [newOrder] = await db.insert(orders).values(order).returning();
    return newOrder;
  }

  async updateOrderStatus(id: number, status: string): Promise<Order> {
    const [updatedOrder] = await db
      .update(orders)
      .set({ status })
      .where(eq(orders.id, id))
      .returning();
    return updatedOrder;
  }

  async getOrderItems(orderId: number): Promise<OrderItem[]> {
    return await db.select().from(orderItems).where(eq(orderItems.orderId, orderId));
  }

  async createOrderItem(orderItem: InsertOrderItem): Promise<OrderItem> {
    const [newOrderItem] = await db.insert(orderItems).values(orderItem).returning();
    return newOrderItem;
  }

  async getAllUsers(): Promise<User[]> {
    return await db.select().from(users);
  }

  async getAllOrders(): Promise<Order[]> {
    return await db.select().from(orders);
  }

  async updateUserRole(userId: number, isAdmin: boolean): Promise<User> {
    const [updatedUser] = await db
      .update(users)
      .set({ isAdmin })
      .where(eq(users.id, userId))
      .returning();
    return updatedUser;
  }

  async getModelConfig(id: number): Promise<ModelConfig | undefined> {
    const [config] = await db.select().from(modelConfigs).where(eq(modelConfigs.id, id));
    return config;
  }

  async getAllModelConfigs(): Promise<ModelConfig[]> {
    return await db.select().from(modelConfigs);
  }

  async getActiveModelConfigs(): Promise<ModelConfig[]> {
    return await db.select().from(modelConfigs).where(eq(modelConfigs.active, true));
  }

  async createModelConfig(config: InsertModelConfig): Promise<ModelConfig> {
    const [newConfig] = await db.insert(modelConfigs).values(config).returning();
    return newConfig;
  }

  async getConversation(id: number): Promise<Conversation | undefined> {
    const [conversation] = await db.select().from(conversations).where(eq(conversations.id, id));
    return conversation;
  }

  async getUserConversations(userId: number): Promise<Conversation[]> {
    return await db.select().from(conversations).where(eq(conversations.userId, userId));
  }

  async createConversation(conversation: InsertConversation): Promise<Conversation> {
    const [newConversation] = await db.insert(conversations).values(conversation).returning();
    return newConversation;
  }

  async getConversationMessages(conversationId: number): Promise<Message[]> {
    return await db.select()
      .from(messages)
      .where(eq(messages.conversationId, conversationId))
      .orderBy(messages.createdAt);
  }

  async createMessage(message: InsertMessage): Promise<Message> {
    const [newMessage] = await db.insert(messages).values(message).returning();
    return newMessage;
  }

  async updateFailedLoginAttempts(userId: number, attempts: number) {
    try {
      await this.pool.query(preparedStatements.updateFailedLoginAttempts, [
        attempts,
        new Date(),
        userId
      ]);
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async resetFailedLoginAttempts(userId: number) {
    try {
      await this.pool.query(preparedStatements.resetFailedLoginAttempts, [userId]);
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async enable2FA(userId: number, secret: string): Promise<void> {
    try {
      await this.pool.query(preparedStatements.enable2FA, [secret, userId]);
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async disable2FA(userId: number): Promise<void> {
    try {
      await this.pool.query(preparedStatements.disable2FA, [userId]);
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async get2FASecret(userId: number): Promise<string | null> {
    try {
      const result = await this.pool.query(preparedStatements.verify2FA, [userId]);
      return result.rows[0]?.two_factor_secret || null;
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async createApiKey(userId: number, key: string, name: string, expiresAt?: Date): Promise<any> {
    try {
      const result = await this.pool.query(preparedStatements.createApiKey, [
        userId,
        key,
        name,
        expiresAt
      ]);
      return result.rows[0];
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async getApiKey(key: string): Promise<any> {
    try {
      const result = await this.pool.query(preparedStatements.getApiKey, [key]);
      return result.rows[0];
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async getUserApiKeys(userId: number): Promise<any[]> {
    try {
      const result = await this.pool.query(preparedStatements.getUserApiKeys, [userId]);
      return result.rows;
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async deactivateApiKey(keyId: number, userId: number): Promise<void> {
    try {
      await this.pool.query(preparedStatements.deactivateApiKey, [keyId, userId]);
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async updateApiKeyLastUsed(keyId: number): Promise<void> {
    try {
      await this.pool.query(preparedStatements.updateApiKeyLastUsed, [keyId]);
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async logSecurityEvent(userId: number, eventType: string, ipAddress: string, userAgent: string, details: any): Promise<void> {
    try {
      await this.pool.query(preparedStatements.logSecurityEvent, [
        userId,
        eventType,
        ipAddress,
        userAgent,
        JSON.stringify(details)
      ]);
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async getSecurityEvents(userId: number, limit: number = 100): Promise<any[]> {
    try {
      const result = await this.pool.query(preparedStatements.getSecurityEvents, [userId, limit]);
      return result.rows;
    } catch (error) {
      handleDatabaseError(error as Error);
    }
  }

  async createSecurityEvent(event: Omit<SecurityEvent, 'id'>): Promise<SecurityEvent> {
    try {
      const result = await this.pool.query<SecurityEvent>(
        preparedStatements.createSecurityEvent,
        [event.eventType, event.userId, event.ipAddress, event.userAgent, event.details, event.severity]
      );
      return result.rows[0];
    } catch (error) {
      handleDatabaseError(error as Error);
      throw error;
    }
  }
}

export const storage = new DatabaseStorage(storagePool);