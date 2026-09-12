import { sqliteTable, int, text, real } from 'drizzle-orm/sqlite-core';

// Users / Organizations table
export const userTable = sqliteTable("users_table", {
    id: int({ mode: "number" }).primaryKey({ autoIncrement: true }),
    name: text("name").notNull(),
    isOrganizationAccount: int("is_organization_account", { mode: "boolean" }).notNull(),
    email: text("email").notNull(),
    passwordHash: text("password_hash").notNull()
});

// Organization members & permissions table
export const organizationMembersTable = sqliteTable("organization_members_table", {
    id: int({ mode: "number" }).primaryKey({ autoIncrement: true }),
    organizationId: int("organization_id").notNull().references(() => userTable.id),
    userId: int("user_id").notNull().references(() => userTable.id),
    permission: text("permission").notNull().default("read"), // "read" (read all) or "write" (global write) or "custom"
    status: text("status").notNull().default("accepted") // "pending" or "accepted"
});

// Per-class write permissions table for organization members
export const memberClassPermissionsTable = sqliteTable("member_class_permissions_table", {
    id: int({ mode: "number" }).primaryKey({ autoIncrement: true }),
    memberId: int("member_id").notNull().references(() => organizationMembersTable.id),
    classId: int("class_id").notNull().references(() => classesTable.id),
    canWrite: int("can_write", { mode: "boolean" }).notNull().default(true)
});

// Academic years table
export const academicYearsTable = sqliteTable("academic_years_table", {
    id: int({ mode: "number" }).primaryKey({ autoIncrement: true }),
    organizationId: int("organization_id").notNull().references(() => userTable.id),
    name: text("name").notNull(), // e.g., "2023 - 2027", "2024 - 2025"
    startDate: text("start_date"),
    endDate: text("end_date")
});

// Classes table
export const classesTable = sqliteTable("classes_table", {
    id: int({ mode: "number" }).primaryKey({ autoIncrement: true }),
    name: text("name").notNull(), // Class name, e.g., "10A1"
    organizationId: int("organization_id").notNull().references(() => userTable.id),
    academicYearId: int("academic_year_id").references(() => academicYearsTable.id),
    academicYear: text("academic_year") // Academic year string representation
});

// Students table
export const studentsTable = sqliteTable("students_table", {
    id: int({ mode: "number" }).primaryKey({ autoIncrement: true }),
    studentCode: text("student_code").notNull().unique(), // Student ID / Code
    name: text("name").notNull(), // Student name
    classId: int("class_id").notNull().references(() => classesTable.id), // Class reference
    dateOfBirth: text("date_of_birth"), // Date of birth (YYYY-MM-DD)
    phone: text("phone"), // Student phone number
    email: text("email"), // Student email
    parentPhone: text("parent_phone"), // Parent phone number
    parentEmail: text("parent_email"), // Parent email
    conductScore: real("conduct_score").default(100), // Conduct score
    conductDeductionReason: text("conduct_deduction_reason") // Lý do trừ điểm hạnh kiểm
});

// Audit change logs table (Google Sheets Version History style)
export const auditLogsTable = sqliteTable("audit_logs_table", {
    id: int({ mode: "number" }).primaryKey({ autoIncrement: true }),
    organizationId: int("organization_id").notNull(),
    userId: int("user_id").notNull(),
    userName: text("user_name"),
    userEmail: text("user_email"),
    action: text("action").notNull(), // "CREATE_STUDENT", "UPDATE_STUDENT", "DELETE_STUDENT", etc.
    entityType: text("entity_type").notNull(), // "student", "class", "academic_year", "member"
    entityId: int("entity_id"),
    classId: int("class_id"),
    description: text("description"),
    beforeState: text("before_state"), // JSON snapshot before change
    afterState: text("after_state"), // JSON snapshot after change
    source: text("source").notNull().default("USER"), // "USER" or "AGENT"
    createdAt: text("created_at").notNull()
});