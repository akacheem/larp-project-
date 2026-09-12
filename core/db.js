import { drizzle } from 'drizzle-orm/libsql';
import { createClient } from '@libsql/client';
import 'dotenv/config';

// Database connection client and drizzle instance setup
const client = createClient({ url: process.env.DATABASE_URL || 'file:./database.db' });
export const db = drizzle({ client });
