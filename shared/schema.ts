import { pgTable, text, serial, integer, boolean, timestamp, decimal, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  email: text("email").notNull().unique(),
  isAdmin: boolean("is_admin").default(false).notNull(),
  isVerified: boolean("is_verified").default(false).notNull(),
});

export const events = pgTable("events", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  location: text("location").notNull(),
  date: timestamp("date").notNull(),
  capacity: integer("capacity").notNull(),
  price: integer("price").notNull(),
  imageUrl: text("image_url").notNull(),
});

export const registrations = pgTable("registrations", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  eventId: integer("event_id").references(() => events.id).notNull(),
  status: text("status").notNull(), // 'pending', 'confirmed', 'cancelled'
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const waitlist = pgTable("waitlist", {
  id: serial("id").primaryKey(),
  email: text("email").notNull().unique(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// New tables for e-commerce
export const products = pgTable("products", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  price: decimal("price").notNull(),
  imageUrl: text("image_url").notNull(),
  category: text("category").notNull(),
  stock: integer("stock").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const orders = pgTable("orders", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  status: text("status").notNull(), // 'pending', 'paid', 'shipped', 'delivered', 'cancelled'
  total: decimal("total").notNull(),
  shippingMethodId: integer("shipping_method_id").references(() => shippingMethods.id),
  shippingAddress: jsonb("shipping_address").notNull(),
  shippingCost: decimal("shipping_cost"),
  trackingNumber: text("tracking_number"),
  estimatedDeliveryDate: timestamp("estimated_delivery_date"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const orderItems = pgTable("order_items", {
  id: serial("id").primaryKey(),
  orderId: integer("order_id").references(() => orders.id).notNull(),
  productId: integer("product_id").references(() => products.id).notNull(),
  quantity: integer("quantity").notNull(),
  price: decimal("price").notNull(), // Price at time of purchase
});

// Add new shipping-related tables
export const shippingMethods = pgTable("shipping_methods", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  carrier: text("carrier").notNull(), // 'USPS', 'UPS', 'FedEx'
  serviceCode: text("service_code").notNull(),
  estimatedDays: integer("estimated_days").notNull(),
  isActive: boolean("is_active").default(true).notNull(),
});

export const shippingZones = pgTable("shipping_zones", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  countries: text("countries").array().notNull(),
  regions: text("regions").array(),
  postalCodes: text("postal_codes").array(),
});

export const shippingRates = pgTable("shipping_rates", {
  id: serial("id").primaryKey(),
  methodId: integer("method_id").references(() => shippingMethods.id).notNull(),
  zoneId: integer("zone_id").references(() => shippingZones.id).notNull(),
  baseRate: decimal("base_rate").notNull(),
  perWeightRate: decimal("per_weight_rate"),
  minimumWeight: decimal("minimum_weight"),
  maximumWeight: decimal("maximum_weight"),
});

// Schema definitions
export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  email: true,
});

export const insertEventSchema = createInsertSchema(events);
export const insertRegistrationSchema = createInsertSchema(registrations);
export const insertWaitlistSchema = createInsertSchema(waitlist).pick({
  email: true,
});

export const insertProductSchema = createInsertSchema(products);
export const insertOrderSchema = createInsertSchema(orders);
export const insertOrderItemSchema = createInsertSchema(orderItems);

// Add shipping-related schemas
export const insertShippingMethodSchema = createInsertSchema(shippingMethods);
export const insertShippingZoneSchema = createInsertSchema(shippingZones);
export const insertShippingRateSchema = createInsertSchema(shippingRates);

// Type definitions
export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertEvent = z.infer<typeof insertEventSchema>;
export type InsertRegistration = z.infer<typeof insertRegistrationSchema>;
export type InsertWaitlist = z.infer<typeof insertWaitlistSchema>;
export type InsertProduct = z.infer<typeof insertProductSchema>;
export type InsertOrder = z.infer<typeof insertOrderSchema>;
export type InsertOrderItem = z.infer<typeof insertOrderItemSchema>;

// Add shipping-related types
export type ShippingMethod = typeof shippingMethods.$inferSelect;
export type ShippingZone = typeof shippingZones.$inferSelect;
export type ShippingRate = typeof shippingRates.$inferSelect;
export type InsertShippingMethod = z.infer<typeof insertShippingMethodSchema>;
export type InsertShippingZone = z.infer<typeof insertShippingZoneSchema>;
export type InsertShippingRate = z.infer<typeof insertShippingRateSchema>;


export type User = typeof users.$inferSelect;
export type Event = typeof events.$inferSelect;
export type Registration = typeof registrations.$inferSelect;
export type Waitlist = typeof waitlist.$inferSelect;
export type Product = typeof products.$inferSelect;
export type Order = typeof orders.$inferSelect;
export type OrderItem = typeof orderItems.$inferSelect;

// Add shipping address schema
export const shippingAddressSchema = z.object({
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().min(1, "Last name is required"),
  address1: z.string().min(1, "Address is required"),
  address2: z.string().optional(),
  city: z.string().min(1, "City is required"),
  state: z.string().min(1, "State is required"),
  postalCode: z.string().min(5, "Valid postal code is required"),
  country: z.string().min(1, "Country is required"),
  phone: z.string().min(10, "Valid phone number is required"),
});

export type ShippingAddress = z.infer<typeof shippingAddressSchema>;


// Add new tables for AI chat functionality
export const modelConfigs = pgTable("model_configs", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  provider: text("provider").notNull(), // 'openai', 'anthropic', etc.
  modelId: text("model_id").notNull(), // 'gpt-4o', 'gpt-3.5-turbo', etc.
  temperature: decimal("temperature").notNull(),
  maxTokens: integer("max_tokens").notNull(),
  active: boolean("active").default(true).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const conversations = pgTable("conversations", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  title: text("title").notNull(),
  modelConfigId: integer("model_config_id").references(() => modelConfigs.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const messages = pgTable("messages", {
  id: serial("id").primaryKey(),
  conversationId: integer("conversation_id").references(() => conversations.id).notNull(),
  role: text("role").notNull(), // 'user', 'assistant', 'system'
  content: text("content").notNull(),
  tokens: integer("tokens"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Add schemas for the new tables
export const insertModelConfigSchema = createInsertSchema(modelConfigs).pick({
  name: true,
  provider: true,
  modelId: true,
  temperature: true,
  maxTokens: true,
  active: true,
});

export const insertConversationSchema = createInsertSchema(conversations).pick({
  userId: true,
  title: true,
  modelConfigId: true,
});

export const insertMessageSchema = createInsertSchema(messages).pick({
  conversationId: true,
  role: true,
  content: true,
  tokens: true,
});

// Add types for the new schemas
export type ModelConfig = typeof modelConfigs.$inferSelect;
export type Conversation = typeof conversations.$inferSelect;
export type Message = typeof messages.$inferSelect;
export type InsertModelConfig = z.infer<typeof insertModelConfigSchema>;
export type InsertConversation = z.infer<typeof insertConversationSchema>;
export type InsertMessage = z.infer<typeof insertMessageSchema>;