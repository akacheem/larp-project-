import 'dotenv/config';
import { hash, compare } from 'bcrypt';
import { userTable } from './schema.js';
import { eq } from 'drizzle-orm';
import { db } from './db.js';

const DEFAULT_SALT_ROUND = 11;

// Authentication functions
export async function newUser(name, isOrganizationAccount, email, password) {
    const trimmedName = (name || '').trim();
    const cleanEmail = (email || '').trim().toLowerCase();

    if (!trimmedName) {
        throw new Error("INVALID_NAME");
    }
    if (!cleanEmail) {
        throw new Error("INVALID_EMAIL");
    }
    if (!password || password.length < 8) {
        throw new Error("PASSWORD_TOO_SHORT");
    }

    if (await isUserAlreadySignup(cleanEmail)) {
        throw new Error("EMAIL_ALREADY_EXISTS");
    }

    let passwordHash;
    try {
        passwordHash = await hash(password, DEFAULT_SALT_ROUND);
    } catch (err) {
        console.error("BCrypt hash error:", err);
        throw new Error("BCRYPT_GEN_HASH_FAIL");
    }

    const user = {
        name: trimmedName,
        isOrganizationAccount: Boolean(isOrganizationAccount),
        email: cleanEmail,
        passwordHash: passwordHash
    };

    try {
        const res = await db.insert(userTable).values(user).returning();
        if (res && res[0]) {
            return res[0];
        }
        // Fallback in case returning is not supported by driver
        const found = await db.select().from(userTable).where(eq(userTable.email, cleanEmail)).limit(1);
        return found[0];
    } catch (err) {
        console.error("Database insert user error:", err);
        if (err.message && (err.message.includes("UNIQUE") || err.message.includes("constraint"))) {
            throw new Error("EMAIL_ALREADY_EXISTS");
        }
        throw new Error("DATABASE_INSERT_FAIL: " + (err.message || err));
    }
}

async function verifyPassword(plainPassword, hashedPassword) {
    try {
        return await compare(plainPassword, hashedPassword);
    } catch (error) {
        console.error("Error during password verification:", error);
        return false;
    }
}

export async function verifyLogin(email, password) {
    const cleanEmail = (email || '').trim().toLowerCase();
    var destUser = await db
        .select()
        .from(userTable)
        .where(eq(userTable.email, cleanEmail))
        .limit(1);

    if (destUser.length < 1)
        return { status: false, user: {} };

    return { status: await verifyPassword(password, destUser[0].passwordHash), user: destUser[0] };
}

export async function isUserAlreadySignup(email) {
    const cleanEmail = (email || '').trim().toLowerCase();
    const existingUser = await db
        .select()
        .from(userTable)
        .where(eq(userTable.email, cleanEmail))
        .limit(1);

    return existingUser.length > 0;
}

export async function listAllUser() {
    console.log(await db.select().from(userTable));
}
