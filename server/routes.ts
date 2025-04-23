import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertUserSchema, insertEventSchema, insertRegistrationSchema, insertWaitlistSchema, insertProductSchema, shippingAddressSchema } from "@shared/schema";
import { z } from "zod";
import Stripe from "stripe";
import { shippingService } from "./services/shipping";
import { body, validationResult, ValidationError } from "express-validator";
import bcrypt from 'bcrypt';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { Session, SessionData } from 'express-session';
import { SecurityEventType, SecurityEventSeverity } from '../src/types/security';
import express from 'express';

// Extend express-session
declare module 'express-session' {
  interface Session {
    userId?: string;
    temp2FASecret?: string;
    isAuthenticated?: boolean;
  }
}

// Base user interface
interface BaseUser {
  id: number;
  username: string;
  password: string;
  email: string;
  isAdmin: boolean;
  isVerified: boolean;
  failedLoginAttempts: number;
  lastFailedLogin: Date | null;
  two_factor_enabled: boolean;
}

// Extended user interface with additional fields
interface User extends BaseUser {
  createdAt: Date;
  updatedAt: Date;
}

// Create user input type
interface CreateUserInput {
  username: string;
  password: string;
  email: string;
  isAdmin: boolean;
  isVerified: boolean;
  failedLoginAttempts: number;
  lastFailedLogin: Date | null;
  two_factor_enabled: boolean;
}

interface SecurityEvent {
  id: number;
  userId: number;
  type: SecurityEventType;
  timestamp: Date;
  details: Record<string, any>;
  severity: SecurityEventSeverity;
  ipAddress: string;
  userAgent: string;
}

interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp?: Date;
}

interface ModelConfig {
  id: number;
  name: string;
  createdAt: Date;
  provider: string;
  modelId: string;
  temperature: number;
  maxTokens: number;
  active: boolean;
  settings: Record<string, any>;
}

interface ApiKeyData {
  id: number;
  user_id: string;
  key: string;
  name: string;
  expires_at: Date | null;
  last_used: Date | null;
  created_at: Date;
  is_active: boolean;
}

interface CustomRequest extends Request {
  session: Session & Partial<SessionData>;
  apiKeyUser?: string;
  user?: User;
}

interface CustomError extends Error {
  status?: number;
  code?: string;
  details?: Record<string, unknown>;
}

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("Warning: Missing STRIPE_SECRET_KEY. Payment features will be disabled.");
  process.env.STRIPE_SECRET_KEY = '';
}

// Initialize Stripe with latest API version
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2025-02-24.acacia'
});

// Add after the imports
const securityEvents: SecurityEvent[] = [];

// Middleware to check if user is authenticated and is an admin
const requireAdmin = async (req: CustomRequest, res: Response, next: NextFunction): Promise<void | Response> => {
  if (!req.session?.userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const baseUser = await storage.getUser(req.session.userId);
    if (!baseUser?.isAdmin) {
      return res.status(403).json({ message: "Forbidden" });
    }

    // Convert BaseUser to User with default values for extended fields
    const user: User = {
      ...baseUser,
      failedLoginAttempts: 0,
      lastFailedLogin: null,
      two_factor_enabled: false,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
};

// Input sanitization middleware
const sanitizeInput = (req: Request, res: Response, next: NextFunction): void => {
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = req.body[key].trim();
      }
    });
  }
  next();
};

// Error handling middleware
const errorHandler = (err: CustomError, req: Request, res: Response, next: NextFunction): void => {
  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    code: err.code,
    details: err.details
  });

  res.status(err.status || 500).json({
    error: err.code || 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'An error occurred',
    details: process.env.NODE_ENV === 'development' ? err.details : undefined
  });
};

// Password complexity validation
const passwordSchema = z.string()
  .min(8, 'Password must be at least 8 characters long')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character');

// Password hashing middleware
const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
};

// Verify password middleware
const verifyPassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

// Security event logging function
const logSecurityEvent = async (
  eventType: SecurityEventType,
  userId: string | null,
  ipAddress: string,
  userAgent: string | undefined,
  details?: Record<string, any>
): Promise<void> => {
  const numericUserId = userId ? parseInt(userId) : null;
  await storage.createSecurityEvent({
    eventType,
    userId: numericUserId,
    ipAddress,
    userAgent: userAgent || '',
    details: details || {},
    severity: 'LOW',
    timestamp: new Date()
  });
};

// API Key Authentication Middleware
const apiKeyAuth = async (req: CustomRequest, res: Response, next: NextFunction): Promise<void | Response> => {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;
  
  if (!apiKey || typeof apiKey !== 'string') {
    return res.status(401).json({ message: 'API key required' });
  }

  try {
    const keyData = await storage.getApiKey(apiKey);
    
    if (!keyData) {
      await logSecurityEvent('API_KEY_INVALID', null, req.ip, req.headers['user-agent'], { apiKey });
      return res.status(401).json({ message: 'Invalid API key' });
    }

    if (keyData.expires_at && new Date(keyData.expires_at) < new Date()) {
      await logSecurityEvent('API_KEY_EXPIRED', keyData.user_id, req.ip, req.headers['user-agent'], { apiKey });
      return res.status(401).json({ message: 'API key expired' });
    }

    // Update last used timestamp
    await storage.updateApiKeyLastUsed(keyData.id);
    
    // Attach user ID to request
    req.apiKeyUser = keyData.user_id;
    next();
  } catch (error) {
    const err = error as CustomError;
    err.status = 500;
    err.code = 'API_KEY_AUTH_ERROR';
    next(err);
  }
};

// Model configuration schema
const modelConfigSchema = z.object({
  id: z.number(),
  name: z.string(),
  createdAt: z.date(),
  provider: z.string(),
  modelId: z.string(),
  temperature: z.number(),
  maxTokens: z.number(),
  active: z.boolean(),
  settings: z.record(z.unknown())
});

// Helper function to convert string to number safely
const safeParseInt = (value: string | undefined): number => {
  if (!value) return 0;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? 0 : parsed;
};

// Helper function to ensure security event type
const ensureSecurityEventType = (type: string): SecurityEventType => {
  const validTypes: SecurityEventType[] = [
    'LOGIN_ATTEMPT',
    'LOGIN_SUCCESS',
    'LOGIN_FAILURE',
    'PASSWORD_RESET',
    'ACCOUNT_LOCKED',
    'SUSPICIOUS_ACTIVITY',
    'API_ACCESS',
    'FILE_ACCESS',
    'DATABASE_ACCESS'
  ];
  return validTypes.includes(type as SecurityEventType) ? type as SecurityEventType : 'SUSPICIOUS_ACTIVITY';
};

// Helper function to ensure security event severity
const ensureSecurityEventSeverity = (severity: string | undefined): SecurityEventSeverity => {
  const validSeverities: SecurityEventSeverity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  return validSeverities.includes(severity as SecurityEventSeverity) ? severity as SecurityEventSeverity : 'LOW';
};

// Helper function to ensure record type
const ensureRecord = (value: Record<string, unknown> | undefined): Record<string, any> => {
  return value || {};
};

// Helper function to ensure model config
const ensureModelConfig = (config: Partial<ModelConfig>): ModelConfig => {
  return {
    id: config.id || 0,
    name: config.name || '',
    createdAt: config.createdAt || new Date(),
    provider: config.provider || '',
    modelId: config.modelId || '',
    temperature: config.temperature || 0,
    maxTokens: config.maxTokens || 0,
    active: config.active || false,
    settings: config.settings || {}
  };
};

export async function registerRoutes(app: Express): Promise<Server> {
  // Apply sanitization middleware to all routes
  app.use(sanitizeInput);

  // Apply error handling middleware
  app.use(errorHandler);

  // Auth routes
  app.post("/api/auth/login", async (req: CustomRequest, res: Response) => {
    try {
      const { username, password } = req.body;
      const user = await storage.getUserByUsername(username);
      
      if (!user) {
        await storage.createSecurityEvent({
          eventType: 'LOGIN_FAILURE',
          userId: null,
          ipAddress: req.ip || '',
          userAgent: req.headers['user-agent'] || '',
          details: { username },
          severity: 'LOW',
          createdAt: new Date()
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const isValidPassword = await verifyPassword(password, user.password);
      if (!isValidPassword) {
        await storage.updateFailedLoginAttempts(user.id, user.failedLoginAttempts + 1);
        await storage.createSecurityEvent({
          eventType: 'LOGIN_FAILURE',
          userId: user.id.toString(),
          ipAddress: req.ip || '',
          userAgent: req.headers['user-agent'] || '',
          details: { username },
          severity: 'MEDIUM',
          createdAt: new Date()
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      if (user.failedLoginAttempts >= 5) {
        await storage.createSecurityEvent({
          eventType: 'ACCOUNT_LOCKED',
          userId: user.id.toString(),
          ipAddress: req.ip || '',
          userAgent: req.headers['user-agent'] || '',
          details: { username },
          severity: 'HIGH',
          createdAt: new Date()
        });
        return res.status(403).json({ error: 'Account locked due to too many failed attempts' });
      }

      await storage.resetFailedLoginAttempts(user.id);
      await storage.createSecurityEvent({
        eventType: 'LOGIN_SUCCESS',
        userId: user.id.toString(),
        ipAddress: req.ip || '',
        userAgent: req.headers['user-agent'] || '',
        details: { username },
        severity: 'LOW',
        createdAt: new Date()
      });

      req.session.userId = user.id.toString();
      req.session.isAuthenticated = true;
      return res.json({ message: 'Login successful' });
    } catch (error) {
      return res.status(500).json({ error: 'Login failed' });
    }
  });

  app.get("/api/auth/me", async (req, res) => {
    if (!req.session?.userId) {
      return res.json(null);
    }

    try {
      const user = await storage.getUser(parseInt(req.session.userId));
      res.json(user || null);
    } catch (error) {
      res.status(500).json({ message: "Failed to get user" });
    }
  });

  app.post("/api/auth/logout", (req, res) => {
    req.session.destroy(() => {
      res.json({ message: "Logged out successfully" });
    });
  });

  // Admin routes
  app.get("/api/users", requireAdmin, async (_req, res) => {
    try {
      const users = await storage.getAllUsers();
      res.json(users);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  app.get("/api/orders", requireAdmin, async (_req, res) => {
    try {
      const orders = await storage.getAllOrders();
      res.json(orders);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch orders" });
    }
  });

  // User routes
  app.post("/api/users", async (req: CustomRequest, res: Response) => {
    try {
      const { username, password, email } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      
      const user: CreateUserInput = {
        username,
        password: hashedPassword,
        email,
        isAdmin: false,
        isVerified: false,
        failedLoginAttempts: 0,
        lastFailedLogin: null,
        two_factor_enabled: false
      };

      const createdUser = await storage.createUser(user);
      return res.status(201).json(createdUser);
    } catch (error) {
      console.error('Error creating user:', error);
      return res.status(500).json({ error: 'Failed to create user' });
    }
  });

  // Event routes
  app.get("/api/events", async (_req, res) => {
    try {
      const events = await storage.getAllEvents();
      res.json(events);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch events" });
    }
  });

  app.post("/api/events", async (req, res) => {
    try {
      const eventData = insertEventSchema.parse(req.body);
      const event = await storage.createEvent(eventData);
      res.status(201).json(event);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid event data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create event" });
    }
  });

  // Registration routes
  app.post("/api/registrations", async (req, res) => {
    try {
      const registrationData = insertRegistrationSchema.parse(req.body);

      const event = await storage.getEvent(registrationData.eventId);
      if (!event) {
        return res.status(404).json({ message: "Event not found" });
      }

      const registrations = await storage.getEventRegistrations(registrationData.eventId);
      if (registrations.length >= event.capacity) {
        return res.status(400).json({ message: "Event is at full capacity" });
      }

      const registration = await storage.createRegistration(registrationData);
      res.status(201).json(registration);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid registration data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create registration" });
    }
  });

  // Waitlist routes
  app.post("/api/waitlist", async (req, res) => {
    try {
      const waitlistData = insertWaitlistSchema.parse(req.body);

      const isEmailRegistered = await storage.isEmailInWaitlist(waitlistData.email);
      if (isEmailRegistered) {
        return res.status(400).json({ message: "Email already in waitlist" });
      }

      const entry = await storage.addToWaitlist(waitlistData);
      res.status(201).json(entry);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid email", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to add to waitlist" });
    }
  });

  // Product routes
  app.post("/api/products", requireAdmin, async (req, res) => {
    try {
      const productData = insertProductSchema.parse(req.body);
      const product = await storage.createProduct(productData);
      res.status(201).json(product);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid product data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create product" });
    }
  });

  app.get("/api/products", async (_req, res) => {
    try {
      const products = await storage.getAllProducts();
      res.json(products);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch products" });
    }
  });

  // Add Stripe payment route
  app.post("/api/create-payment-intent", async (req, res) => {
    try {
      const { amount } = req.body;

      if (!amount || amount <= 0) {
        return res.status(400).json({ message: "Invalid amount" });
      }

      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100), // Convert to cents
        currency: "usd",
        // Add automatic payment methods
        automatic_payment_methods: {
          enabled: true,
        },
      });

      res.json({ clientSecret: paymentIntent.client_secret });
    } catch (error: any) {
      console.error("Stripe error:", error);
      res.status(500).json({
        message: "Error creating payment intent",
        details: error.message
      });
    }
  });

  // Shipping routes
  app.post("/api/shipping/validate-address", async (req, res) => {
    try {
      const address = shippingAddressSchema.parse(req.body);
      const validatedAddress = await shippingService.validateAddress(address);
      res.json(validatedAddress);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid address data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to validate address" });
    }
  });

  app.post("/api/shipping/calculate-rates", async (req, res) => {
    try {
      const { fromAddress, toAddress, parcelDetails } = req.body;

      // Validate addresses
      const validFromAddress = shippingAddressSchema.parse(fromAddress);
      const validToAddress = shippingAddressSchema.parse(toAddress);

      const rates = await shippingService.getShippingRates(
        validFromAddress,
        validToAddress,
        parcelDetails
      );

      res.json(rates);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid address data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to calculate shipping rates" });
    }
  });


  // Chat routes
  app.get("/api/models", async (req, res) => {
    try {
      const models = await storage.getActiveModelConfigs();
      res.json(models);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch models" });
    }
  });

  app.get("/api/conversations", async (req, res) => {
    if (!req.session?.userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const conversations = await storage.getUserConversations(parseInt(req.session.userId));
      res.json(conversations);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch conversations" });
    }
  });

  app.post("/api/conversations", async (req, res) => {
    if (!req.session?.userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const conversationData = {
        ...req.body,
        userId: parseInt(req.session.userId),
      };
      const conversation = await storage.createConversation(conversationData);
      res.status(201).json(conversation);
    } catch (error) {
      res.status(500).json({ message: "Failed to create conversation" });
    }
  });

  app.get("/api/conversations/:id/messages", async (req, res) => {
    if (!req.session?.userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const conversation = await storage.getConversation(parseInt(req.params.id));
      if (!conversation || conversation.userId !== parseInt(req.session.userId)) {
        return res.status(403).json({ message: "Forbidden" });
      }

      const messages = await storage.getConversationMessages(conversation.id);
      res.json(messages);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch messages" });
    }
  });

  app.post("/api/conversations/:id/messages", async (req, res) => {
    if (!req.session?.userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const conversation = await storage.getConversation(parseInt(req.params.id));
      if (!conversation || conversation.userId !== parseInt(req.session.userId)) {
        return res.status(403).json({ message: "Forbidden" });
      }

      // Create user message
      const userMessage = await storage.createMessage({
        conversationId: conversation.id,
        role: 'user',
        content: req.body.content,
        tokens: await countTokens(req.body.content),
      });

      // Get model config and generate response
      const modelConfig = await storage.getModelConfig(conversation.modelConfigId);
      if (!modelConfig) {
        throw new Error("Model configuration not found");
      }

      const messages = await storage.getConversationMessages(conversation.id);
      const response = await generateChatResponse(
        messages.map(m => ({ role: m.role as 'user' | 'assistant' | 'system', content: m.content })),
        modelConfig
      );

      // Create assistant message
      const assistantMessage = await storage.createMessage({
        conversationId: conversation.id,
        role: 'assistant',
        content: response,
        tokens: await countTokens(response),
      });

      res.json({
        userMessage,
        assistantMessage,
      });
    } catch (error: any) {
      res.status(500).json({ message: error.message || "Failed to process message" });
    }
  });

  // Add Stripe webhook route with enhanced security
  app.post("/api/webhook", 
    express.raw({ type: 'application/json' }), 
    async (req, res) => {
      const sig = req.headers['stripe-signature'];
      const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

      if (!sig || !endpointSecret) {
        return res.status(400).send('Webhook signature or secret missing');
      }

      let event;

      try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
      } catch (err: any) {
        console.error(`Webhook Error: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
      }

      // Validate event data
      if (!event || !event.type || !event.data || !event.data.object) {
        return res.status(400).send('Invalid event data');
      }

      // Handle the event with additional validation
      switch (event.type) {
        case 'payment_intent.succeeded':
          const paymentIntent = event.data.object;
          if (!paymentIntent.amount || !paymentIntent.currency) {
            return res.status(400).send('Invalid payment intent data');
          }
          console.log(`PaymentIntent for ${paymentIntent.amount} was successful!`);
          // Handle successful payment
          break;
        case 'payment_intent.payment_failed':
          const failedPayment = event.data.object;
          if (!failedPayment.amount || !failedPayment.currency) {
            return res.status(400).send('Invalid payment intent data');
          }
          console.log(`Payment failed for ${failedPayment.amount}`);
          // Handle failed payment
          break;
        case 'checkout.session.completed':
          const session = event.data.object;
          if (!session.id || !session.customer) {
            return res.status(400).send('Invalid session data');
          }
          console.log(`Checkout session completed: ${session.id}`);
          // Handle completed checkout
          break;
        default:
          console.log(`Unhandled event type ${event.type}`);
      }

      // Return a 200 response to acknowledge receipt of the event
      res.json({ received: true });
    }
  );

  // 2FA routes
  app.post('/api/auth/2fa/enable', async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
      // Generate a secret
      const secret = speakeasy.generateSecret({
        name: 'Jesus Walks Napa'
      });

      // Generate QR code
      const qrCode = await QRCode.toDataURL(secret.otpauth_url);

      // Store the secret temporarily in the session
      req.session.temp2FASecret = secret.base32;

      res.json({
        secret: secret.base32,
        qrCode
      });
    } catch (error) {
      console.error('2FA enable error:', error);
      res.status(500).json({ message: 'Failed to enable 2FA' });
    }
  });

  app.post('/api/auth/2fa/verify', async (req, res) => {
    if (!req.session.userId || !req.session.temp2FASecret) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const { token } = req.body;

    try {
      // Verify the token
      const verified = speakeasy.totp.verify({
        secret: req.session.temp2FASecret,
        encoding: 'base32',
        token
      });

      if (verified) {
        // Store the secret permanently
        await storage.enable2FA(parseInt(req.session.userId), req.session.temp2FASecret);
        delete req.session.temp2FASecret;
        res.json({ message: '2FA enabled successfully' });
      } else {
        res.status(400).json({ message: 'Invalid token' });
      }
    } catch (error) {
      console.error('2FA verify error:', error);
      res.status(500).json({ message: 'Failed to verify 2FA' });
    }
  });

  app.post('/api/auth/2fa/disable', async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
      await storage.disable2FA(parseInt(req.session.userId));
      res.json({ message: '2FA disabled successfully' });
    } catch (error) {
      console.error('2FA disable error:', error);
      res.status(500).json({ message: 'Failed to disable 2FA' });
    }
  });

  // API Key Routes
  app.post('/api/keys', async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
      const { name, expiresInDays } = req.body;
      
      // Generate a secure API key
      const key = crypto.randomBytes(32).toString('hex');
      
      // Calculate expiration date if provided
      const expiresAt = expiresInDays 
        ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
        : undefined;

      const apiKey = await storage.createApiKey(parseInt(req.session.userId), key, name, expiresAt);
      
      await logSecurityEvent('API_KEY_CREATED', req.session.userId, req.ip, req.headers['user-agent'], { keyId: apiKey.id, name });

      res.json({
        id: apiKey.id,
        key,
        name: apiKey.name,
        expiresAt: apiKey.expires_at
      });
    } catch (error) {
      console.error('API key creation error:', error);
      res.status(500).json({ message: 'Failed to create API key' });
    }
  });

  app.get('/api/keys', async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
      const keys = await storage.getUserApiKeys(parseInt(req.session.userId));
      res.json(keys.map(key => ({
        id: key.id,
        name: key.name,
        lastUsed: key.last_used,
        expiresAt: key.expires_at,
        isActive: key.is_active
      })));
    } catch (error) {
      console.error('API key fetch error:', error);
      res.status(500).json({ message: 'Failed to fetch API keys' });
    }
  });

  app.delete('/api/keys/:id', async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
      await storage.deactivateApiKey(parseInt(req.params.id), parseInt(req.session.userId));
      
      await logSecurityEvent('API_KEY_DEACTIVATED', req.session.userId, req.ip, req.headers['user-agent'], { keyId: req.params.id });

      res.json({ message: 'API key deactivated' });
    } catch (error) {
      console.error('API key deactivation error:', error);
      res.status(500).json({ message: 'Failed to deactivate API key' });
    }
  });

  // Security Events Route
  app.post('/api/security-events', async (req, res) => {
    try {
      const { userId, type, details, severity, ipAddress, userAgent } = req.body;

      // Validate required fields
      if (!userId || !type || !ipAddress || !userAgent) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      // Validate and convert types
      const validatedUserId = Number(userId);
      if (isNaN(validatedUserId)) {
        return res.status(400).json({ error: 'Invalid user ID' });
      }

      const validatedType = type.toUpperCase() as SecurityEventType;
      if (!['LOGIN', 'LOGOUT', 'PASSWORD_CHANGE', 'TWO_FACTOR_ENABLED', 'TWO_FACTOR_DISABLED', 'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED'].includes(validatedType)) {
        return res.status(400).json({ error: 'Invalid event type' });
      }

      const validatedSeverity = (severity?.toUpperCase() || 'LOW') as SecurityEventSeverity;
      if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(validatedSeverity)) {
        return res.status(400).json({ error: 'Invalid severity level' });
      }

      // Create security event
      const event: SecurityEvent = {
        id: Date.now(), // Temporary ID until we have a database
        userId: validatedUserId,
        type: validatedType,
        timestamp: new Date(),
        details: details || {},
        severity: validatedSeverity,
        ipAddress: ipAddress as string,
        userAgent: userAgent as string
      };

      // Store event (in memory for now)
      securityEvents.push(event);

      res.status(201).json(event);
    } catch (error) {
      console.error('Error creating security event:', error);
      res.status(500).json({ error: 'Failed to create security event' });
    }
  });

  // Example of a protected route using API key authentication
  app.get('/api/protected', apiKeyAuth, async (req, res) => {
    try {
      // This route is only accessible with a valid API key
      res.json({ message: 'Access granted with API key' });
    } catch (error) {
      console.error('Protected route error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}

// Placeholder functions -  Replace with your actual implementations
async function countTokens(text: string): Promise<number> {
  // Simple implementation - replace with actual token counting logic
  return text.split(/\s+/).length;
}

async function generateChatResponse(
  messages: ChatMessage[], 
  modelConfig: ModelConfig
): Promise<string> {
  // Implementation to generate a chat response using the modelConfig
  // This is a placeholder - replace with actual implementation
  return "This is a placeholder response.";
}