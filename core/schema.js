import { sqliteTable, int, text } from 'drizzle-orm/sqlite-core';

// schema
export const userTable = sqliteTable("users_table", {
    id: int({ mode: "number" }).primaryKey({ autoIncrement: true }),
    name: text("name").notNull(),
    isOrganizationAccount: int("is_organization_account", { mode: "boolean" }).notNull(),
    email: text("email").notNull(),
    passwordHash: text("password_hash").notNull()
});