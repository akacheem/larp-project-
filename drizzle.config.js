import 'dotenv/config';
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
    out: './core',
    schema: './core/schema.js',
    dialect: process.env.DATABASE_URL?.startsWith('libsql:') ? 'turso' : 'sqlite',
    dbCredentials: {
        url: process.env.DATABASE_URL || "file:./database.db",
        ...(process.env.TURSO_AUTH_TOKEN ? { authToken: process.env.TURSO_AUTH_TOKEN } : {}),
    },
});