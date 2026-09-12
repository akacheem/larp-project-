import { db } from './db.js';
import { auditLogsTable, studentsTable, classesTable, academicYearsTable, userTable } from './schema.js';
import { eq, and, desc } from 'drizzle-orm';
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

    return deleted;
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
