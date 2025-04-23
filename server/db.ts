import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from "ws";
import * as schema from "@shared/schema";

neonConfig.webSocketConstructor = ws;

// In production, we require DATABASE_URL to be set
if (process.env.NODE_ENV === 'production' && !process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL must be set in production environment");
  throw new Error(
    "DATABASE_URL must be set. Please add this secret to your deployment.",
  );
}

// Use DATABASE_URL or a fallback for development
const connectionString = process.env.DATABASE_URL || 
  (process.env.NODE_ENV === 'production' ? '' : 'postgresql://postgres:postgres@localhost:5432/myapp');

if (!connectionString) {
  throw new Error('Database connection string is required');
}

export const pool = new Pool({ connectionString });
export const db = drizzle(pool, { schema });
