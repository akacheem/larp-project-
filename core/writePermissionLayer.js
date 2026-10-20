import { db } from './db.js';
import { auditLogsTable, studentsTable, classesTable, academicYearsTable, userTable, monthlyConductSummariesTable } from './schema.js';
import { eq, and, desc } from 'drizzle-orm';
import { syncBroker } from './syncBroker.js';
import {
    checkUserClassAccess,
    checkUserStudentAccess,
    createClass,
    updateClass,
    deleteClass,
    createAcademicYear,
    deleteAcademicYear,
    addStudentToClass,
    updateStudent,
    deleteStudent,
    inviteUserToOrganization,
    setMemberClassPermissions,
    removeOrganizationMember,
    getUserById
} from './organization.js';

/**
 * DATABASE WRITE PERMISSION LAYER & AUDIT LOGGER
 * 
 * Enforces strict permission validation before executing any write operation.
 * Logs all modifications (before & after states) to the audit trail table.
 * Supports execution under acting user credentials (USER or AGENT/AI).
 */

export async function logAuditChange({
    actorUser,
    organizationId,
    action,
    entityType,
    entityId = null,
    classId = null,
    description = '',
    beforeState = null,
    afterState = null,
    source = 'USER'
}) {
    try {
        await db.insert(auditLogsTable).values({
            organizationId: Number(organizationId),
            userId: Number(actorUser.id),
            userName: actorUser.name || actorUser.username || actorUser.email,
            userEmail: actorUser.email,
            action,
            entityType,
            entityId: entityId ? Number(entityId) : null,
            classId: classId ? Number(classId) : null,
            description,
            beforeState: beforeState ? JSON.stringify(beforeState) : null,
            afterState: afterState ? JSON.stringify(afterState) : null,
            source,
            createdAt: new Date().toISOString()
        });
    } catch (err) {
        console.error('[Audit Logger Error]', err);
    }
}

// 1. Secure Create Class
export async function secureCreateClass(actorUser, { name, academicYearId, academicYear }, source = 'USER') {
    const dbUser = await getUserById(actorUser.id);
    if (!dbUser || !dbUser.isOrganizationAccount) {
        throw new Error('CHỈ_TỔ_CHỨC_MỚI_CÓ_QUYỀN: Chỉ tài khoản Tổ chức mới có quyền tạo lớp học mới.');
    }

    const created = await createClass(dbUser.id, name, academicYearId, academicYear);

    await logAuditChange({
        actorUser: dbUser,
        organizationId: dbUser.id,
        action: 'CREATE_CLASS',
        entityType: 'class',
        entityId: created.id,
        classId: created.id,
        description: `Tạo lớp học mới: "${created.name}"`,
        beforeState: null,
        afterState: created,
        source
    });

    syncBroker.broadcastSyncEvent({
        orgId: dbUser.id,
        type: 'CLASS_MUTATED',
        senderUserId: dbUser.id,
        message: `Đã tạo lớp học mới "${created.name}".`
    });

    return created;
}

// 2. Secure Update Class
export async function secureUpdateClass(actorUser, classId, { name, academicYearId }, source = 'USER') {
    const access = await checkUserClassAccess(actorUser.id, classId);
    if (!access.isOwner) {
        throw new Error('CHỈ_TỔ_CHỨC_MỚI_CÓ_QUYỀN: Chỉ chủ sở hữu Tổ chức mới có quyền sửa thông tin lớp học.');
    }

    const beforeCls = access.class;
    const updated = await updateClass(access.organizationId, classId, name, academicYearId);

    await logAuditChange({
        actorUser,
        organizationId: access.organizationId,
        action: 'UPDATE_CLASS',
        entityType: 'class',
        entityId: classId,
        classId: Number(classId),
        description: `Cập nhật thông tin lớp học "${beforeCls.name}" ➔ "${updated.name}"`,
        beforeState: beforeCls,
        afterState: updated,
        source
    });

    syncBroker.broadcastSyncEvent({
        orgId: access.organizationId,
        classId: Number(classId),
        type: 'CLASS_MUTATED',
        senderUserId: actorUser.id,
        message: `Đã cập nhật thông tin lớp học "${updated.name}".`
    });

    return updated;
}

// 3. Secure Delete Class
export async function secureDeleteClass(actorUser, classId, source = 'USER') {
    const access = await checkUserClassAccess(actorUser.id, classId);
    if (!access.isOwner) {
        throw new Error('CHỈ_TỔ_CHỨC_MỚI_CÓ_QUYỀN: Chỉ chủ sở hữu Tổ chức mới có quyền xóa lớp học.');
    }

    const beforeCls = access.class;
    const deleted = await deleteClass(access.organizationId, classId);

    await logAuditChange({
        actorUser,
        organizationId: access.organizationId,
        action: 'DELETE_CLASS',
        entityType: 'class',
        entityId: classId,
        classId: Number(classId),
        description: `Xóa lớp học "${beforeCls.name}"`,
        beforeState: beforeCls,
        afterState: null,
        source
    });

    syncBroker.broadcastSyncEvent({
        orgId: access.organizationId,
        classId: Number(classId),
        type: 'CLASS_MUTATED',
        senderUserId: actorUser.id,
        message: `Đã xóa lớp học "${beforeCls.name}".`
    });

    return deleted;
}

// 4. Secure Create Academic Year
export async function secureCreateAcademicYear(actorUser, { name, startDate, endDate }, source = 'USER') {
    const dbUser = await getUserById(actorUser.id);
    if (!dbUser || !dbUser.isOrganizationAccount) {
        throw new Error('CHỈ_TỔ_CHỨC_MỚI_CÓ_QUYỀN: Chỉ tài khoản Tổ chức mới có quyền tạo niên khóa.');
    }

    const created = await createAcademicYear(dbUser.id, name, startDate, endDate);

    await logAuditChange({
        actorUser: dbUser,
        organizationId: dbUser.id,
        action: 'CREATE_ACADEMIC_YEAR',
        entityType: 'academic_year',
        entityId: created.id,
        description: `Tạo niên khóa mới: "${created.name}"`,
        beforeState: null,
        afterState: created,
        source
    });

    return created;
}

// 5. Secure Delete Academic Year (Chỉ tài khoản Tổ chức sở hữu mới có quyền xóa niên khóa)
export async function secureDeleteAcademicYear(actorUser, academicYearId, source = 'USER') {
    const dbUser = await getUserById(actorUser.id);
    if (!dbUser || !dbUser.isOrganizationAccount) {
        throw new Error('CHỈ_TỔ_CHỨC_MỚI_CÓ_QUYỀN: Chỉ tài khoản Tổ chức mới có quyền xóa niên khóa.');
    }

    const deleted = await deleteAcademicYear(dbUser.id, Number(academicYearId));
    if (!deleted) {
        throw new Error('Niên khóa không tồn tại hoặc đã bị xóa.');
    }

    await logAuditChange({
        actorUser: dbUser,
        organizationId: dbUser.id,
        action: 'DELETE_ACADEMIC_YEAR',
        entityType: 'academic_year',
        entityId: Number(academicYearId),
        description: `Xóa niên khóa: "${deleted.name}"`,
        beforeState: deleted,
        afterState: null,
        source
    });

    return deleted;
}

// 5. Secure Add Student (Chỉ người sở hữu Tổ chức mới có quyền thêm học sinh)
export async function secureAddStudent(actorUser, studentData, source = 'USER') {
    const { classId } = studentData;
    const access = await checkUserClassAccess(actorUser.id, classId);
    if (!access.isOwner) {
        throw new Error('KHÔNG_CÓ_QUYỀN: Chỉ người sở hữu Tổ chức mới được phép thêm học sinh.');
    }

    const created = await addStudentToClass(access.organizationId, studentData);

    await logAuditChange({
        actorUser,
        organizationId: access.organizationId,
        action: 'ADD_STUDENT',
        entityType: 'student',
        entityId: created.id,
        classId: Number(classId),
        description: `Thêm học sinh mới "${created.name}" (${created.studentCode}) vào lớp #${classId}`,
        beforeState: null,
        afterState: created,
        source
    });

    syncBroker.broadcastSyncEvent({
        orgId: access.organizationId,
        classId: Number(classId),
        type: 'STUDENTS_UPDATED',
        senderUserId: actorUser.id,
        data: { studentId: created.id },
        message: `Đã thêm học sinh mới "${created.name}".`
    });

    return created;
}

// 6. Secure Update Student
export async function secureUpdateStudent(actorUser, studentId, studentData, source = 'USER') {
    const access = await checkUserStudentAccess(actorUser.id, studentId);
    if (!access.canWrite) {
        throw new Error('KHÔNG_CÓ_QUYỀN_GHI: Bạn không có quyền chỉnh sửa thông tin học sinh này.');
    }

    // Nếu không phải Owner, chỉ cho phép chỉnh sửa điểm hạnh kiểm và lý do trừ điểm
    if (!access.isOwner) {
        const restrictedFields = ['name', 'studentCode', 'dateOfBirth', 'phone', 'email', 'parentPhone', 'parentEmail'];
        const isAttemptingRestrictedEdit = restrictedFields.some(field => studentData[field] !== undefined);
        if (isAttemptingRestrictedEdit) {
            throw new Error('KHÔNG_CÓ_QUYỀN: Chỉ người sở hữu Tổ chức mới có quyền sửa thông tin cá nhân của học sinh. Thành viên chỉ được quyền chỉnh sửa điểm hạnh kiểm.');
        }
    }

    // Get before state snapshot
    const beforeStudents = await db
        .select()
        .from(studentsTable)
        .where(eq(studentsTable.id, Number(studentId)))
        .limit(1);

    const beforeState = beforeStudents[0] || null;
    const updated = await updateStudent(access.organizationId, studentId, studentData);

    await logAuditChange({
        actorUser,
        organizationId: access.organizationId,
        action: 'UPDATE_STUDENT',
        entityType: 'student',
        entityId: Number(studentId),
        classId: updated.classId,
        description: `Cập nhật học sinh "${updated.name}" (${updated.studentCode})`,
        beforeState,
        afterState: updated,
        source
    });

    syncBroker.broadcastSyncEvent({
        orgId: access.organizationId,
        classId: updated.classId,
        type: 'STUDENTS_UPDATED',
        senderUserId: actorUser.id,
        data: { studentId: updated.id },
        message: `Đã cập nhật thông tin học sinh "${updated.name}".`
    });

    return updated;
}

// 6b. Secure Deduct Conduct Score (Cả Người sở hữu Tổ chức VÀ Thành viên có quyền ghi đều được phép trừ điểm)
export async function secureDeductConductScore(actorUser, studentId, points, reason, source = 'USER') {
    const access = await checkUserStudentAccess(actorUser.id, studentId);
    if (!access.canWrite) {
        throw new Error('KHÔNG_CÓ_QUYỀN_GHI: Bạn không có quyền trừ điểm hạnh kiểm học sinh này.');
    }

    const beforeStudents = await db
        .select()
        .from(studentsTable)
        .where(eq(studentsTable.id, Number(studentId)))
        .limit(1);

    const beforeState = beforeStudents[0];
    if (!beforeState) {
        throw new Error('Học sinh không tồn tại');
    }

    const currentScore = Number(beforeState.conductScore ?? 100);
    const pts = Math.max(0, Number(points) || 0);
    const newScore = Math.max(0, currentScore - pts);

    const updated = await updateStudent(access.organizationId, studentId, {
        conductScore: newScore,
        conductDeductionReason: reason ? reason.trim() : 'Trừ điểm hạnh kiểm'
    });

    await logAuditChange({
        actorUser,
        organizationId: access.organizationId,
        action: 'DEDUCT_CONDUCT_SCORE',
        entityType: 'student',
        entityId: Number(studentId),
        classId: updated.classId,
        description: `Trừ ${pts} điểm hạnh kiểm của "${updated.name}" (${updated.studentCode}). Lý do: ${reason}`,
        beforeState,
        afterState: updated,
        source
    });

    syncBroker.broadcastSyncEvent({
        orgId: access.organizationId,
        classId: updated.classId,
        type: 'STUDENTS_UPDATED',
        senderUserId: actorUser.id,
        data: { studentId: updated.id, newScore },
        message: `Trừ ${pts} điểm hạnh kiểm của ${updated.name}`
    });

    return updated;
}

// 7. Secure Delete Student (Chỉ người sở hữu Tổ chức mới được phép xóa)
export async function secureDeleteStudent(actorUser, studentId, source = 'USER') {
    const access = await checkUserStudentAccess(actorUser.id, studentId);
    if (!access.isOwner) {
        throw new Error('KHÔNG_CÓ_QUYỀN: Chỉ người sở hữu Tổ chức mới có quyền xóa học sinh.');
    }

    const beforeStudents = await db
        .select()
        .from(studentsTable)
        .where(eq(studentsTable.id, Number(studentId)))
        .limit(1);

    const beforeState = beforeStudents[0] || null;
    const deleted = await deleteStudent(access.organizationId, studentId);

    await logAuditChange({
        actorUser,
        organizationId: access.organizationId,
        action: 'DELETE_STUDENT',
        entityType: 'student',
        entityId: Number(studentId),
        classId: beforeState ? beforeState.classId : null,
        description: `Xóa học sinh "${beforeState ? beforeState.name : studentId}" khỏi lớp`,
        beforeState,
        afterState: null,
        source
    });

    syncBroker.broadcastSyncEvent({
        orgId: access.organizationId,
        classId: beforeState ? beforeState.classId : null,
        type: 'STUDENTS_UPDATED',
        senderUserId: actorUser.id,
        data: { deletedStudentId: studentId },
        message: `Đã xóa học sinh khỏi lớp.`
    });

    return deleted;
}

// 7b. Secure Batch Save Students (Atomic Transaction with Single Permission Check & Multi-client Event Sync)
export async function secureBatchSaveStudents(actorUser, classId, { creates = [], updates = [], deletes = [] } = {}, source = 'USER') {
    const numClassId = Number(classId);
    if (!numClassId || isNaN(numClassId)) {
        throw new Error('ID lớp học không hợp lệ');
    }

    const access = await checkUserClassAccess(actorUser.id, numClassId);
    if (!access.canWrite) {
        throw new Error('KHÔNG_CÓ_QUYỀN_GHI: Bạn không có quyền chỉnh sửa học sinh trong lớp học này.');
    }

    // Non-owner restriction
    if (!access.isOwner) {
        if (creates && creates.length > 0) {
            throw new Error('KHÔNG_CÓ_QUYỀN: Chỉ người sở hữu Tổ chức mới được phép thêm học sinh mới.');
        }
        if (deletes && deletes.length > 0) {
            throw new Error('KHÔNG_CÓ_QUYỀN: Chỉ người sở hữu Tổ chức mới được phép xóa học sinh.');
        }
        const restrictedFields = ['name', 'studentCode', 'dateOfBirth', 'phone', 'email', 'parentPhone', 'parentEmail'];
        for (const upd of (updates || [])) {
            const isAttemptingRestrictedEdit = restrictedFields.some(field => upd[field] !== undefined);
            if (isAttemptingRestrictedEdit) {
                throw new Error('KHÔNG_CÓ_QUYỀN: Chỉ người sở hữu Tổ chức mới có quyền sửa thông tin cá nhân của học sinh. Thành viên chỉ được quyền chỉnh sửa điểm hạnh kiểm.');
            }
        }
    }

    // Execute atomically inside database transaction
    const result = await db.transaction(async (tx) => {
        const createdResults = [];
        const updatedResults = [];
        const deletedResults = [];
        const auditEntries = [];

        // 1. Process deletes
        if (Array.isArray(deletes)) {
            for (const studentId of deletes) {
                const numId = Number(studentId);
                if (!numId) continue;
                const existing = await tx.select().from(studentsTable)
                    .where(and(eq(studentsTable.id, numId), eq(studentsTable.classId, numClassId)))
                    .limit(1);
                if (existing.length > 0) {
                    const beforeState = existing[0];
                    await tx.delete(studentsTable).where(eq(studentsTable.id, numId));
                    deletedResults.push(numId);
                    auditEntries.push({
                        action: 'DELETE_STUDENT',
                        entityType: 'student',
                        entityId: numId,
                        classId: numClassId,
                        description: `Xóa học sinh "${beforeState.name}" (${beforeState.studentCode}) [Batch Save]`,
                        beforeState,
                        afterState: null
                    });
                }
            }
        }

        // 2. Process updates
        if (Array.isArray(updates)) {
            for (const upd of updates) {
                const numId = Number(upd.id);
                if (!numId) continue;
                const existing = await tx.select().from(studentsTable)
                    .where(and(eq(studentsTable.id, numId), eq(studentsTable.classId, numClassId)))
                    .limit(1);
                if (existing.length === 0) continue;
                const beforeState = existing[0];

                const updateData = {};
                if (access.isOwner) {
                    if (upd.name !== undefined) updateData.name = upd.name ? upd.name.trim() : beforeState.name;
                    if (upd.studentCode !== undefined) updateData.studentCode = upd.studentCode ? upd.studentCode.trim() : beforeState.studentCode;
                    if (upd.dateOfBirth !== undefined) updateData.dateOfBirth = upd.dateOfBirth || null;
                    if (upd.phone !== undefined) updateData.phone = upd.phone || null;
                    if (upd.email !== undefined) updateData.email = upd.email || null;
                    if (upd.parentPhone !== undefined) updateData.parentPhone = upd.parentPhone || null;
                    if (upd.parentEmail !== undefined) updateData.parentEmail = upd.parentEmail || null;
                }
                if (upd.conductScore !== undefined) updateData.conductScore = Number(upd.conductScore);
                if (upd.conductDeductionReason !== undefined) {
                    updateData.conductDeductionReason = upd.conductDeductionReason ? upd.conductDeductionReason.trim() : null;
                }

                const updated = await tx.update(studentsTable)
                    .set(updateData)
                    .where(eq(studentsTable.id, numId))
                    .returning();

                if (updated && updated[0]) {
                    updatedResults.push(updated[0]);
                    auditEntries.push({
                        action: 'UPDATE_STUDENT',
                        entityType: 'student',
                        entityId: numId,
                        classId: numClassId,
                        description: `Cập nhật học sinh "${updated[0].name}" (${updated[0].studentCode}) [Batch Save]`,
                        beforeState,
                        afterState: updated[0]
                    });
                }
            }
        }

        // 3. Process creates
        if (Array.isArray(creates)) {
            for (const item of creates) {
                if (!item.name || !item.name.trim()) continue;
                const created = await tx.insert(studentsTable).values({
                    studentCode: item.studentCode ? item.studentCode.trim() : `HS${Date.now().toString().slice(-6)}${Math.floor(Math.random() * 1000)}`,
                    name: item.name.trim(),
                    classId: numClassId,
                    dateOfBirth: item.dateOfBirth || null,
                    phone: item.phone || null,
                    email: item.email || null,
                    parentPhone: item.parentPhone || null,
                    parentEmail: item.parentEmail || null,
                    conductScore: item.conductScore !== undefined ? Number(item.conductScore) : 100,
                    conductDeductionReason: item.conductDeductionReason ? item.conductDeductionReason.trim() : null
                }).returning();

                if (created && created[0]) {
                    createdResults.push(created[0]);
                    auditEntries.push({
                        action: 'ADD_STUDENT',
                        entityType: 'student',
                        entityId: created[0].id,
                        classId: numClassId,
                        description: `Thêm học sinh mới "${created[0].name}" (${created[0].studentCode}) [Batch Save]`,
                        beforeState: null,
                        afterState: created[0]
                    });
                }
            }
        }

        // 4. Batch insert audit logs
        for (const audit of auditEntries) {
            await tx.insert(auditLogsTable).values({
                organizationId: Number(access.organizationId),
                userId: Number(actorUser.id),
                userName: actorUser.name || actorUser.username || actorUser.email,
                userEmail: actorUser.email,
                action: audit.action,
                entityType: audit.entityType,
                entityId: audit.entityId ? Number(audit.entityId) : null,
                classId: audit.classId ? Number(audit.classId) : null,
                description: audit.description,
                beforeState: audit.beforeState ? JSON.stringify(audit.beforeState) : null,
                afterState: audit.afterState ? JSON.stringify(audit.afterState) : null,
                source,
                createdAt: new Date().toISOString()
            });
        }

        return {
            createdCount: createdResults.length,
            updatedCount: updatedResults.length,
            deletedCount: deletedResults.length,
            creates: createdResults,
            updates: updatedResults,
            deletes: deletedResults
        };
    });

    // Broadcast Real-time sync event
    syncBroker.broadcastSyncEvent({
        orgId: access.organizationId,
        classId: numClassId,
        type: 'STUDENTS_UPDATED',
        senderUserId: actorUser.id,
        data: {
            createdCount: result.createdCount,
            updatedCount: result.updatedCount,
            deletedCount: result.deletedCount
        },
        message: `Đã lưu đồng bộ ${result.createdCount + result.updatedCount + result.deletedCount} thay đổi học sinh.`
    });

    return result;
}

// 8. Secure Invite Member
export async function secureInviteMember(actorUser, { email, permission }, source = 'USER') {
    const dbUser = await getUserById(actorUser.id);
    if (!dbUser || !dbUser.isOrganizationAccount) {
        throw new Error('CHỈ_TỔ_CHỨC_MỚI_CÓ_QUYỀN: Chỉ tài khoản Tổ chức mới có quyền mời thành viên.');
    }

    const invited = await inviteUserToOrganization(dbUser.id, email, permission);

    await logAuditChange({
        actorUser: dbUser,
        organizationId: dbUser.id,
        action: 'INVITE_MEMBER',
        entityType: 'member',
        entityId: invited.id,
        description: `Mời thành viên mới "${email}" vào tổ chức`,
        beforeState: null,
        afterState: invited,
        source
    });

    return invited;
}

// 9. Secure Set Member Class Permissions
export async function secureSetMemberClassPermissions(actorUser, memberRecordId, allowedClassIds = [], source = 'USER') {
    const dbUser = await getUserById(actorUser.id);
    if (!dbUser || !dbUser.isOrganizationAccount) {
        throw new Error('CHỈ_TỔ_CHỨC_MỚI_CÓ_QUYỀN: Chỉ tài khoản Tổ chức mới có quyền phân quyền theo lớp.');
    }

    const res = await setMemberClassPermissions(dbUser.id, memberRecordId, allowedClassIds);

    await logAuditChange({
        actorUser: dbUser,
        organizationId: dbUser.id,
        action: 'SET_CLASS_PERMISSIONS',
        entityType: 'member',
        entityId: memberRecordId,
        description: `Cập nhật quyền ghi theo lớp cho thành viên #${memberRecordId}`,
        beforeState: null,
        afterState: res,
        source
    });

    return res;
}

// 10. Secure Remove Member
export async function secureRemoveMember(actorUser, memberRecordId, source = 'USER') {
    const dbUser = await getUserById(actorUser.id);
    if (!dbUser || !dbUser.isOrganizationAccount) {
        throw new Error('CHỈ_TỔ_CHỨC_MỚI_CÓ_QUYỀN: Chỉ tài khoản Tổ chức mới có quyền xóa thành viên.');
    }

    const deleted = await removeOrganizationMember(dbUser.id, memberRecordId);

    await logAuditChange({
        actorUser: dbUser,
        organizationId: dbUser.id,
        action: 'REMOVE_MEMBER',
        entityType: 'member',
        entityId: memberRecordId,
        description: `Xóa thành viên #${memberRecordId} khỏi tổ chức`,
        beforeState: deleted,
        afterState: null,
        source
    });

    return deleted;
}

// Get Audit Logs with Field Diffs (Google Sheets Version History Style)
export async function getAuditLogs(actorUser, { classId = null, limit = 100 } = {}) {
    let query = db
        .select()
        .from(auditLogsTable);

    if (classId) {
        query = query.where(eq(auditLogsTable.classId, Number(classId)));
    }

    const logs = await query.orderBy(desc(auditLogsTable.id)).limit(limit);

    // Filter logs accessible to user & generate Google Sheets style diffs
    const resultLogs = [];

    for (let log of logs) {
        // Permission check: User can read logs if they own org or are accepted member
        if (log.classId) {
            const access = await checkUserClassAccess(actorUser.id, log.classId);
            if (!access.canRead) continue;
        } else {
            const dbUser = await getUserById(actorUser.id);
            if (dbUser && !dbUser.isOrganizationAccount && actorUser.id !== log.userId) {
                continue;
            }
        }

        let beforeObj = null;
        let afterObj = null;

        try { if (log.beforeState) beforeObj = JSON.parse(log.beforeState); } catch {}
        try { if (log.afterState) afterObj = JSON.parse(log.afterState); } catch {}

        // Compute granular field diffs (Google Sheets Revision Style)
        const diffs = [];
        const fieldLabels = {
            studentCode: 'Mã Học sinh',
            name: 'Họ và Tên',
            dateOfBirth: 'Ngày sinh',
            phone: 'SĐT Học sinh',
            email: 'Email Học sinh',
            parentPhone: 'SĐT Phụ huynh',
            parentEmail: 'Email Phụ huynh',
            conductScore: 'Điểm hạnh kiểm',
            conductDeductionReason: 'Lý do trừ điểm hạnh kiểm',
            academicYear: 'Niên khóa'
        };

        if (beforeObj && afterObj) {
            const allKeys = new Set([...Object.keys(beforeObj), ...Object.keys(afterObj)]);
            const skipKeys = ['id', 'organizationId', 'classId'];

            for (let key of allKeys) {
                if (skipKeys.includes(key)) continue;
                const oldVal = beforeObj[key];
                const newVal = afterObj[key];
                if (oldVal !== newVal && (oldVal != null || newVal != null)) {
                    diffs.push({
                        field: key,
                        label: fieldLabels[key] || key,
                        oldValue: oldVal ?? '(trống)',
                        newValue: newVal ?? '(trống)'
                    });
                }
            }
        }

        resultLogs.push({
            ...log,
            beforeState: beforeObj,
            afterState: afterObj,
            diffs
        });
    }

    return resultLogs;
}

/**
 * 11. Helper to calculate conduct rank based on score:
 * - 90 - 100: Tốt
 * - 80 - dưới 90: Khá
 * - 70 - dưới 80: Đạt
 * - dưới 70: Chưa đạt
 */
export function calculateConductRank(score) {
    const s = Number(score ?? 100);
    if (s >= 90) return 'Tốt';
    if (s >= 80) return 'Khá';
    if (s >= 70) return 'Đạt';
    return 'Chưa đạt';
}

/**
 * 12. Get Monthly Conduct Data (Historical snapshot if closed, or live calculation preview if active)
 */
export async function getMonthlyConductData(actorUser, classId, month, year) {
    const access = await checkUserClassAccess(actorUser.id, classId);
    if (!access.canRead) {
        throw new Error('Bạn không có quyền xem thông tin lớp học này.');
    }

    const numClassId = Number(classId);
    const m = Number(month);
    const y = Number(year);
    const monthLabel = `Tháng ${m < 10 ? '0' + m : m}/${y}`;

    // Check if there are already saved summary records for this class & month
    const existing = await db
        .select()
        .from(monthlyConductSummariesTable)
        .where(
            and(
                eq(monthlyConductSummariesTable.classId, numClassId),
                eq(monthlyConductSummariesTable.month, m),
                eq(monthlyConductSummariesTable.year, y)
            )
        );

    if (existing.length > 0) {
        // Closed historical snapshot
        const first = existing[0];
        const stats = {
            total: existing.length,
            tot: existing.filter(r => r.conductRank === 'Tốt').length,
            kha: existing.filter(r => r.conductRank === 'Khá').length,
            dat: existing.filter(r => r.conductRank === 'Đạt').length,
            chuaDat: existing.filter(r => r.conductRank === 'Chưa đạt').length
        };

        const summaries = existing.map(item => ({
            id: item.id,
            studentId: item.studentId,
            studentCode: item.studentCode,
            studentName: item.studentName,
            finalScore: item.finalScore,
            conductRank: item.conductRank,
            deductions: item.deductionHistoryJson ? JSON.parse(item.deductionHistoryJson) : [],
            closedAt: item.closedAt
        }));

        return {
            isClosed: true,
            month: m,
            year: y,
            monthLabel,
            closedInfo: {
                closedAt: first.closedAt,
                closedByUserName: first.closedByUserName || 'Giáo viên'
            },
            stats,
            summaries
        };
    }

    // Live preview from current students in class
    const students = await db
        .select()
        .from(studentsTable)
        .where(eq(studentsTable.classId, numClassId));

    // Get deduction audit logs for this class
    const logs = await db
        .select()
        .from(auditLogsTable)
        .where(
            and(
                eq(auditLogsTable.classId, numClassId),
                eq(auditLogsTable.action, 'DEDUCT_CONDUCT_SCORE')
            )
        );

    const summaries = students.map(st => {
        const score = Number(st.conductScore ?? 100);
        const rank = calculateConductRank(score);

        // Filter deduction logs for this student
        const studentLogs = logs.filter(l => Number(l.entityId) === Number(st.id)).map(l => ({
            reason: l.description,
            time: l.createdAt,
            actorName: l.userName
        }));

        return {
            studentId: st.id,
            studentCode: st.studentCode,
            studentName: st.name,
            finalScore: score,
            conductRank: rank,
            deductions: studentLogs,
            currentReason: st.conductDeductionReason
        };
    });

    const stats = {
        total: summaries.length,
        tot: summaries.filter(r => r.conductRank === 'Tốt').length,
        kha: summaries.filter(r => r.conductRank === 'Khá').length,
        dat: summaries.filter(r => r.conductRank === 'Đạt').length,
        chuaDat: summaries.filter(r => r.conductRank === 'Chưa đạt').length
    };

    return {
        isClosed: false,
        month: m,
        year: y,
        monthLabel,
        closedInfo: null,
        stats,
        summaries
    };
}

/**
 * 13. Secure Close Monthly Conduct & Reset Scores to 100
 */
export async function secureCloseMonthlyConduct(actorUser, classId, month, year, source = 'USER') {
    const access = await checkUserClassAccess(actorUser.id, classId);
    if (!access.canWrite) {
        throw new Error('Bạn không có quyền chốt sổ hạnh kiểm lớp học này.');
    }

    const numClassId = Number(classId);
    const m = Number(month);
    const y = Number(year);
    const monthLabel = `Tháng ${m < 10 ? '0' + m : m}/${y}`;

    // Check if already closed
    const existing = await db
        .select()
        .from(monthlyConductSummariesTable)
        .where(
            and(
                eq(monthlyConductSummariesTable.classId, numClassId),
                eq(monthlyConductSummariesTable.month, m),
                eq(monthlyConductSummariesTable.year, y)
            )
        )
        .limit(1);

    if (existing.length > 0) {
        throw new Error(`Hạnh kiểm ${monthLabel} của lớp này đã được chốt sổ trước đó.`);
    }

    const students = await db
        .select()
        .from(studentsTable)
        .where(eq(studentsTable.classId, numClassId));

    if (students.length === 0) {
        throw new Error('Lớp học chưa có học sinh nào để chốt điểm.');
    }

    // Get deduction logs
    const logs = await db
        .select()
        .from(auditLogsTable)
        .where(
            and(
                eq(auditLogsTable.classId, numClassId),
                eq(auditLogsTable.action, 'DEDUCT_CONDUCT_SCORE')
            )
        );

    const nowIso = new Date().toISOString();
    const actorName = actorUser.name || actorUser.username || actorUser.email;

    const summaryInserts = students.map(st => {
        const score = Number(st.conductScore ?? 100);
        const rank = calculateConductRank(score);

        const studentLogs = logs.filter(l => Number(l.entityId) === Number(st.id)).map(l => ({
            reason: l.description,
            time: l.createdAt,
            actorName: l.userName
        }));

        return {
            organizationId: access.organizationId,
            classId: numClassId,
            month: m,
            year: y,
            monthLabel,
            studentId: st.id,
            studentCode: st.studentCode,
            studentName: st.name,
            finalScore: score,
            conductRank: rank,
            deductionHistoryJson: JSON.stringify(studentLogs),
            closedAt: nowIso,
            closedByUserId: Number(actorUser.id),
            closedByUserName: actorName
        };
    });

    // Insert all summary records
    for (const record of summaryInserts) {
        await db.insert(monthlyConductSummariesTable).values(record);
    }

    // RESET all students in this class back to 100 conduct score and clear deduction reason
    await db
        .update(studentsTable)
        .set({
            conductScore: 100,
            conductDeductionReason: null
        })
        .where(eq(studentsTable.classId, numClassId));

    // Audit log
    await logAuditChange({
        actorUser,
        organizationId: access.organizationId,
        action: 'CLOSE_MONTHLY_CONDUCT',
        entityType: 'class',
        entityId: numClassId,
        classId: numClassId,
        description: `Chốt sổ & Đánh giá hạnh kiểm ${monthLabel} cho ${students.length} học sinh và đặt lại điểm về 100`,
        beforeState: { studentCount: students.length, month: m, year: y },
        afterState: { monthLabel, closedAt: nowIso, resetScore: 100 },
        source
    });

    syncBroker.broadcastSyncEvent({
        orgId: access.organizationId,
        classId: numClassId,
        type: 'MONTHLY_CONDUCT_CLOSED',
        senderUserId: actorUser.id,
        message: `Đã chốt sổ hạnh kiểm ${monthLabel} và đặt lại điểm về 100.`
    });

    return {
        success: true,
        monthLabel,
        closedAt: nowIso,
        studentCount: students.length,
        message: `Đã chốt sổ hạnh kiểm ${monthLabel} thành công và đặt lại điểm về 100!`
    };
}

/**
 * 14. Secure Reopen Monthly Conduct (Owner only)
 */
export async function secureReopenMonthlyConduct(actorUser, classId, month, year, source = 'USER') {
    const access = await checkUserClassAccess(actorUser.id, classId);
    if (!access.isOwner) {
        throw new Error('Chỉ Người sở hữu Tổ chức mới có quyền mở lại sổ hạnh kiểm đã chốt.');
    }

    const numClassId = Number(classId);
    const m = Number(month);
    const y = Number(year);

    // Delete existing records for that month
    await db
        .delete(monthlyConductSummariesTable)
        .where(
            and(
                eq(monthlyConductSummariesTable.classId, numClassId),
                eq(monthlyConductSummariesTable.month, m),
                eq(monthlyConductSummariesTable.year, y)
            )
        );

    await logAuditChange({
        actorUser,
        organizationId: access.organizationId,
        action: 'REOPEN_MONTHLY_CONDUCT',
        entityType: 'class',
        entityId: numClassId,
        classId: numClassId,
        description: `Mở lại sổ hạnh kiểm Tháng ${m}/${y} cho lớp`,
        source
    });

    return { success: true, message: `Đã mở lại sổ hạnh kiểm Tháng ${m}/${y}.` };
}

