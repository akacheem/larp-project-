import 'dotenv/config';
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
    out: './core',
    schema: './core/schema.js',
    dialect: 'sqlite',
    dbCredentials: {
        url: process.env.DATABASE_URL || "file:./database.db",
    },
});