import { drizzle } from 'drizzle-orm/libsql';
import { createClient } from '@libsql/client';
import 'dotenv/config';
import { hash } from 'bcrypt';
import { userTable } from './schema.js';
import { eq } from 'drizzle-orm';

const client = createClient({ url: process.env.DATABASE_URL || 'file:./database.db' })
const db = drizzle({ client });
const DEFAULT_SALT_ROUND = 11

// auth func
export async function newUser(name, isOrganizationAccount, email, password) {
    let passwordHash;
    try {
        passwordHash = await hash(password, DEFAULT_SALT_ROUND)
    }
    catch {
        throw new Error("BCRYPT_GEN_HASH_FAIL")
    }

    var user = userTable.$inferInsert = {
        name: name,
        isOrganizationAccount: isOrganizationAccount,
        email: email,
        passwordHash: passwordHash
    }

    try {
        await db.insert(userTable).values(user)
    } catch {
        throw new Error("DATABASE_INSERT_FAIL")
    }
}

export async function isUserAlreadySignup(email) {
    const existingUser = await db
        .select()
        .from(userTable)
        .where(eq(userTable.email, email))
        .limit(1)

    return existingUser.length > 0
}

export async function listAllUser() {
    console.log(await db.select().from(userTable))
}