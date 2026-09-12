import { db } from './db.js';
import { userTable, academicYearsTable, classesTable, organizationMembersTable, memberClassPermissionsTable, studentsTable } from './schema.js';
import { eq, and, inArray } from 'drizzle-orm';

// Get user details by ID
export async function getUserById(userId) {
    const users = await db
        .select({
            id: userTable.id,
            name: userTable.name,
            email: userTable.email,
            isOrganizationAccount: userTable.isOrganizationAccount
        })
        .from(userTable)
        .where(eq(userTable.id, userId))
        .limit(1);

    return users.length > 0 ? users[0] : null;
}

// Get user by Email
export async function getUserByEmail(email) {
    const users = await db
        .select()
        .from(userTable)
        .where(eq(userTable.email, email))
        .limit(1);

    return users.length > 0 ? users[0] : null;
}

// Create Academic Year (Only Organization Owner)
export async function createAcademicYear(organizationId, name, startDate = null, endDate = null) {
    const result = await db.insert(academicYearsTable).values({
        organizationId,
        name,
        startDate,
        endDate
    }).returning();
    return result[0];
}

// Get Academic Years for Organization
export async function getAcademicYears(organizationId) {
    return await db
        .select()
        .from(academicYearsTable)
        .where(eq(academicYearsTable.organizationId, organizationId));
}

// Create Class (ONLY Organization Owner has permission to add classes)
export async function createClass(organizationId, name, academicYearId = null, academicYear = null) {
    const result = await db.insert(classesTable).values({
        organizationId,
        name,
        academicYearId,
        academicYear
    }).returning();
    return result[0];
}

// Get Classes for Organization
export async function getClasses(organizationId) {
    return await db
        .select()
        .from(classesTable)
        .where(eq(classesTable.organizationId, organizationId));
}

// Invite user to Organization
export async function inviteUserToOrganization(organizationId, targetEmail, permission = "read") {
    const targetUser = await getUserByEmail(targetEmail);
    if (!targetUser) {
        throw new Error("USER_NOT_FOUND");
    }

    if (targetUser.isOrganizationAccount) {
        throw new Error("CANNOT_INVITE_ORGANIZATION_ACCOUNT");
    }

    // Check if already invited or member
    const existing = await db
        .select()
        .from(organizationMembersTable)
        .where(
            and(
                eq(organizationMembersTable.organizationId, organizationId),
                eq(organizationMembersTable.userId, targetUser.id)
            )
        )
        .limit(1);

    if (existing.length > 0) {
        throw new Error("USER_ALREADY_INVITED");
    }

    const inserted = await db.insert(organizationMembersTable).values({
        organizationId,
        userId: targetUser.id,
        permission: permission,
        status: "accepted"
    }).returning();

    return {
        ...inserted[0],
        user: {
            id: targetUser.id,
            name: targetUser.name,
            email: targetUser.email
        },
        allowedClassIds: []
    };
}

// Get Organization Members with User details & per-class write permissions
export async function getOrganizationMembers(organizationId) {
    const members = await db
        .select({
            id: organizationMembersTable.id,
            organizationId: organizationMembersTable.organizationId,
            userId: organizationMembersTable.userId,
            permission: organizationMembersTable.permission,
            status: organizationMembersTable.status,
            userName: userTable.name,
            userEmail: userTable.email,
            isOrganizationAccount: userTable.isOrganizationAccount
        })
        .from(organizationMembersTable)
        .innerJoin(userTable, eq(organizationMembersTable.userId, userTable.id))
        .where(eq(organizationMembersTable.organizationId, organizationId));

    // Fetch class permissions for each member
    for (let member of members) {
        const classPerms = await db
            .select({ classId: memberClassPermissionsTable.classId })
            .from(memberClassPermissionsTable)
            .where(
                and(
                    eq(memberClassPermissionsTable.memberId, member.id),
                    eq(memberClassPermissionsTable.canWrite, true)
                )
            );
        member.allowedClassIds = classPerms.map(p => p.classId);
    }

    return members;
}

// Update Member Permission ("read" | "write")
export async function updateMemberPermission(organizationId, memberRecordId, permission) {
    if (!["read", "write"].includes(permission)) {
        throw new Error("INVALID_PERMISSION");
    }

    const updated = await db
        .update(organizationMembersTable)
        .set({ permission })
        .where(
            and(
                eq(organizationMembersTable.id, memberRecordId),
                eq(organizationMembersTable.organizationId, organizationId)
            )
        )
        .returning();

    if (updated.length === 0) {
        throw new Error("MEMBER_NOT_FOUND");
    }

    return updated[0];
}

// Update per-class write permissions for a member
export async function setMemberClassPermissions(organizationId, memberRecordId, allowedClassIds = []) {
    // Check member belongs to org
    const member = await db
        .select()
        .from(organizationMembersTable)
        .where(
            and(
                eq(organizationMembersTable.id, memberRecordId),
                eq(organizationMembersTable.organizationId, organizationId)
            )
        )
        .limit(1);

    if (member.length === 0) {
        throw new Error("MEMBER_NOT_FOUND");
    }

    // Clear old permissions
    await db
        .delete(memberClassPermissionsTable)
        .where(eq(memberClassPermissionsTable.memberId, memberRecordId));

    // Insert new permissions
    if (Array.isArray(allowedClassIds) && allowedClassIds.length > 0) {
        const toInsert = allowedClassIds.map(classId => ({
            memberId: memberRecordId,
            classId: Number(classId),
            canWrite: true
        }));
        await db.insert(memberClassPermissionsTable).values(toInsert);
    }

    return { memberId: memberRecordId, allowedClassIds };
}

// Remove Organization Member
export async function removeOrganizationMember(organizationId, memberRecordId) {
    // Delete per-class permissions first
    await db
        .delete(memberClassPermissionsTable)
        .where(eq(memberClassPermissionsTable.memberId, memberRecordId));

    const deleted = await db
        .delete(organizationMembersTable)
        .where(
            and(
                eq(organizationMembersTable.id, memberRecordId),
                eq(organizationMembersTable.organizationId, organizationId)
            )
        )
        .returning();

    if (deleted.length === 0) {
        throw new Error("MEMBER_NOT_FOUND");
    }

    return deleted[0];
}

// Update Class Name & Academic Year
export async function updateClass(organizationId, classId, name, academicYearId = null) {
    const updated = await db
        .update(classesTable)
        .set({
            name: name.trim(),
            academicYearId: academicYearId ? Number(academicYearId) : null
        })
        .where(
            and(
                eq(classesTable.id, Number(classId)),
                eq(classesTable.organizationId, organizationId)
            )
        )
        .returning();

    if (updated.length === 0) {
        throw new Error("Lớp học không tồn tại hoặc không có quyền sửa");
    }
    return updated[0];
}

// Update Student Info
export async function updateStudent(organizationId, studentId, studentData) {
    const { studentCode, name, dateOfBirth, phone, email, parentPhone, parentEmail, conductScore, conductDeductionReason } = studentData;

    // Verify student belongs to an org class
    const student = await db
        .select({ id: studentsTable.id })
        .from(studentsTable)
        .innerJoin(classesTable, eq(studentsTable.classId, classesTable.id))
        .where(
            and(
                eq(studentsTable.id, Number(studentId)),
                eq(classesTable.organizationId, organizationId)
            )
        )
        .limit(1);

    if (student.length === 0) {
        throw new Error("Học sinh không tồn tại");
    }

    const updated = await db
        .update(studentsTable)
        .set({
            studentCode: studentCode ? studentCode.trim() : undefined,
            name: name ? name.trim() : undefined,
            dateOfBirth: dateOfBirth || null,
            phone: phone || null,
            email: email || null,
            parentPhone: parentPhone || null,
            parentEmail: parentEmail || null,
            conductScore: conductScore !== undefined ? Number(conductScore) : undefined,
            conductDeductionReason: conductDeductionReason !== undefined ? (conductDeductionReason ? conductDeductionReason.trim() : null) : undefined
        })
        .where(eq(studentsTable.id, Number(studentId)))
        .returning();

    return updated[0];
}

// Delete Class (Used for Undo/Revert)
export async function deleteClass(organizationId, classId) {
    // Delete students in class first
    await db.delete(studentsTable).where(eq(studentsTable.classId, Number(classId)));

    const deleted = await db
        .delete(classesTable)
        .where(
            and(
                eq(classesTable.id, Number(classId)),
                eq(classesTable.organizationId, organizationId)
            )
        )
        .returning();
    return deleted[0] || null;
}

// Delete Academic Year (Unlinks classes first)
export async function deleteAcademicYear(organizationId, academicYearId) {
    // Unlink classes referencing this academic year
    await db
        .update(classesTable)
        .set({ academicYearId: null })
        .where(
            and(
                eq(classesTable.academicYearId, Number(academicYearId)),
                eq(classesTable.organizationId, organizationId)
            )
        );

    const deleted = await db
        .delete(academicYearsTable)
        .where(
            and(
                eq(academicYearsTable.id, Number(academicYearId)),
                eq(academicYearsTable.organizationId, organizationId)
            )
        )
        .returning();
    return deleted[0] || null;
}

// Add Student to Class (Only Organization Account)
export async function addStudentToClass(organizationId, studentData) {
    const { classId, studentCode, name, dateOfBirth, phone, email, parentPhone, parentEmail, conductScore, conductDeductionReason } = studentData;

    // Verify class belongs to organization
    const cls = await db
        .select()
        .from(classesTable)
        .where(
            and(
                eq(classesTable.id, Number(classId)),
                eq(classesTable.organizationId, organizationId)
            )
        )
        .limit(1);

    if (cls.length === 0) {
        throw new Error("Lớp học không tồn tại hoặc không thuộc tổ chức của bạn");
    }

    const inserted = await db
        .insert(studentsTable)
        .values({
            studentCode: studentCode || `HS${Date.now().toString().slice(-6)}`,
            name,
            classId: Number(classId),
            dateOfBirth: dateOfBirth || null,
            phone: phone || null,
            email: email || null,
            parentPhone: parentPhone || null,
            parentEmail: parentEmail || null,
            conductScore: conductScore !== undefined ? Number(conductScore) : 100,
            conductDeductionReason: conductDeductionReason ? conductDeductionReason.trim() : null
        })
        .returning();

    return inserted[0];
}

// Get Students for a Class
export async function getStudentsByClass(organizationId, classId) {
    // Verify class ownership
    const cls = await db
        .select()
        .from(classesTable)
        .where(
            and(
                eq(classesTable.id, Number(classId)),
                eq(classesTable.organizationId, organizationId)
            )
        )
        .limit(1);

    if (cls.length === 0) {
        return [];
    }

    return await db
        .select()
        .from(studentsTable)
        .where(eq(studentsTable.classId, Number(classId)));
}

// Delete Student from Class
export async function deleteStudent(organizationId, studentId) {
    const student = await db
        .select({
            id: studentsTable.id,
            classId: studentsTable.classId
        })
        .from(studentsTable)
        .innerJoin(classesTable, eq(studentsTable.classId, classesTable.id))
        .where(
            and(
                eq(studentsTable.id, Number(studentId)),
                eq(classesTable.organizationId, organizationId)
            )
        )
        .limit(1);

    if (student.length === 0) {
        throw new Error("Học sinh không tồn tại");
    }

    const deleted = await db
        .delete(studentsTable)
        .where(eq(studentsTable.id, Number(studentId)))
        .returning();

    return deleted[0] || null;
}

// --- NON-ORGANIZATION MEMBER & PERMISSION HELPERS ---

// Get Organizations that a non-organization user belongs to (accepted status)
export async function getUserOrganizations(userId) {
    const memberships = await db
        .select({
            memberRecordId: organizationMembersTable.id,
            organizationId: organizationMembersTable.organizationId,
            permission: organizationMembersTable.permission,
            status: organizationMembersTable.status,
            organizationName: userTable.name,
            organizationEmail: userTable.email
        })
        .from(organizationMembersTable)
        .innerJoin(userTable, eq(organizationMembersTable.organizationId, userTable.id))
        .where(
            and(
                eq(organizationMembersTable.userId, userId),
                eq(organizationMembersTable.status, "accepted")
            )
        );

    for (let m of memberships) {
        const perms = await db
            .select({ classId: memberClassPermissionsTable.classId })
            .from(memberClassPermissionsTable)
            .where(
                and(
                    eq(memberClassPermissionsTable.memberId, m.memberRecordId),
                    eq(memberClassPermissionsTable.canWrite, true)
                )
            );
        m.allowedClassIds = perms.map(p => p.classId);
    }

    return memberships;
}

// Get Accessible Classes for a User (Owner or Member)
export async function getAccessibleClassesForUser(user) {
    if (!user) return [];

    if (user.isOrganizationAccount) {
        const classes = await getClasses(user.id);
        return classes.map(c => ({
            ...c,
            canWrite: true,
            organizationName: user.name || "Tổ chức của bạn"
        }));
    }

    // Non-organization user
    const memberships = await getUserOrganizations(user.id);
    if (memberships.length === 0) return [];

    const accessibleClasses = [];
    for (let m of memberships) {
        const classes = await getClasses(m.organizationId);
        for (let c of classes) {
            const canWrite = m.permission === "write" || m.allowedClassIds.includes(c.id);
            accessibleClasses.push({
                ...c,
                canWrite,
                organizationId: m.organizationId,
                organizationName: m.organizationName
            });
        }
    }
    return accessibleClasses;
}

// Get Accessible Academic Years for User (Owner or Member)
export async function getAccessibleAcademicYearsForUser(user) {
    if (!user) return [];

    if (user.isOrganizationAccount) {
        return await getAcademicYears(user.id);
    }

    const memberships = await getUserOrganizations(user.id);
    if (memberships.length === 0) return [];

    const years = [];
    for (let m of memberships) {
        const orgYears = await getAcademicYears(m.organizationId);
        years.push(...orgYears);
    }
    return years;
}

// Check Class Access Permission for a User
export async function checkUserClassAccess(userId, classId) {
    const numClassId = Number(classId);
    const cls = await db
        .select()
        .from(classesTable)
        .where(eq(classesTable.id, numClassId))
        .limit(1);

    if (cls.length === 0) {
        return { canRead: false, canWrite: false, organizationId: null, isOwner: false, class: null };
    }

    const targetClass = cls[0];

    // Check if user is the Organization Owner
    if (targetClass.organizationId === userId) {
        return { canRead: true, canWrite: true, organizationId: targetClass.organizationId, isOwner: true, class: targetClass };
    }

    // Check if user is an accepted member of the Organization
    const membership = await db
        .select()
        .from(organizationMembersTable)
        .where(
            and(
                eq(organizationMembersTable.organizationId, targetClass.organizationId),
                eq(organizationMembersTable.userId, userId),
                eq(organizationMembersTable.status, "accepted")
            )
        )
        .limit(1);

    if (membership.length === 0) {
        return { canRead: false, canWrite: false, organizationId: targetClass.organizationId, isOwner: false, class: targetClass };
    }

    const memberRecord = membership[0];

    // Global write permission
    if (memberRecord.permission === "write") {
        return { canRead: true, canWrite: true, organizationId: targetClass.organizationId, isOwner: false, class: targetClass };
    }

    // Custom class permission
    const classPerm = await db
        .select()
        .from(memberClassPermissionsTable)
        .where(
            and(
                eq(memberClassPermissionsTable.memberId, memberRecord.id),
                eq(memberClassPermissionsTable.classId, numClassId),
                eq(memberClassPermissionsTable.canWrite, true)
            )
        )
        .limit(1);

    const canWrite = classPerm.length > 0;
    return { canRead: true, canWrite, organizationId: targetClass.organizationId, isOwner: false, class: targetClass };
}

// Check Student Access Permission for a User
export async function checkUserStudentAccess(userId, studentId) {
    const student = await db
        .select({ id: studentsTable.id, classId: studentsTable.classId })
        .from(studentsTable)
        .where(eq(studentsTable.id, Number(studentId)))
        .limit(1);

    if (student.length === 0) {
        return { canRead: false, canWrite: false, organizationId: null, isOwner: false, student: null };
    }

    const access = await checkUserClassAccess(userId, student[0].classId);
    return { ...access, student: student[0] };
}

