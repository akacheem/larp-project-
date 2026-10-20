import { drizzle } from 'drizzle-orm/libsql';
import { createClient } from '@libsql/client';
import 'dotenv/config';

const url = process.env.DATABASE_URL || 'file:./database.db';
const authToken = process.env.TURSO_AUTH_TOKEN || undefined;

// Database connection client and drizzle instance setup
export const client = createClient({
    url,
    ...(authToken ? { authToken } : {})
});

export const db = drizzle({ client });

/**
 * Automatically creates all tables if they do not exist.
 * Essential for fresh cloud databases like Turso.
 */
export async function initDatabase() {
    try {
        await client.batch([
            `CREATE TABLE IF NOT EXISTS users_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                is_organization_account INTEGER NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );`,
            `CREATE TABLE IF NOT EXISTS academic_years_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL REFERENCES users_table(id),
                name TEXT NOT NULL,
                start_date TEXT,
                end_date TEXT
            );`,
            `CREATE TABLE IF NOT EXISTS classes_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                organization_id INTEGER NOT NULL REFERENCES users_table(id),
                academic_year_id INTEGER REFERENCES academic_years_table(id),
                academic_year TEXT
            );`,
            `CREATE TABLE IF NOT EXISTS organization_members_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL REFERENCES users_table(id),
                user_id INTEGER NOT NULL REFERENCES users_table(id),
                permission TEXT NOT NULL DEFAULT 'read',
                status TEXT NOT NULL DEFAULT 'accepted'
            );`,
            `CREATE TABLE IF NOT EXISTS member_class_permissions_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                member_id INTEGER NOT NULL REFERENCES organization_members_table(id),
                class_id INTEGER NOT NULL REFERENCES classes_table(id),
                can_write INTEGER NOT NULL DEFAULT 1
            );`,
            `CREATE TABLE IF NOT EXISTS students_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_code TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                class_id INTEGER NOT NULL REFERENCES classes_table(id),
                date_of_birth TEXT,
                phone TEXT,
                email TEXT,
                parent_phone TEXT,
                parent_email TEXT,
                conduct_score REAL DEFAULT 100,
                conduct_deduction_reason TEXT
            );`,
            `CREATE TABLE IF NOT EXISTS audit_logs_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                user_name TEXT,
                user_email TEXT,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER,
                class_id INTEGER,
                description TEXT,
                before_state TEXT,
                after_state TEXT,
                source TEXT NOT NULL DEFAULT 'USER',
                created_at TEXT NOT NULL
            );`,
            `CREATE TABLE IF NOT EXISTS monthly_conduct_summaries_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                class_id INTEGER NOT NULL REFERENCES classes_table(id),
                month INTEGER NOT NULL,
                year INTEGER NOT NULL,
                month_label TEXT NOT NULL,
                student_id INTEGER NOT NULL REFERENCES students_table(id),
                student_code TEXT NOT NULL,
                student_name TEXT NOT NULL,
                final_score REAL NOT NULL,
                conduct_rank TEXT NOT NULL,
                deduction_history_json TEXT,
                closed_at TEXT NOT NULL,
                closed_by_user_id INTEGER NOT NULL,
                closed_by_user_name TEXT
            );`
        ]);
        console.log('✅ Cơ sở dữ liệu (Database) đã được đồng bộ cấu trúc bảng thành công.');
    } catch (err) {
        console.error('⚠️ Khởi tạo cấu trúc bảng cơ sở dữ liệu có thông báo:', err.message || err);
    }
}
