import { isUserAlreadySignup, newUser, verifyLogin } from "../core/auth.js";
import {
    getUserById,
    getClasses,
    getAcademicYears,
    getOrganizationMembers,
    getStudentsByClass,
    getUserOrganizations,
    getAccessibleClassesForUser,
    getAccessibleAcademicYearsForUser,
    checkUserClassAccess,
    checkUserStudentAccess
} from "../core/organization.js";

import {
    secureCreateClass,
    secureUpdateClass,
    secureDeleteClass,
    secureCreateAcademicYear,
    secureAddStudent,
    secureUpdateStudent,
    secureDeleteStudent,
    secureBatchSaveStudents,
    secureDeductConductScore,
    secureInviteMember,
    secureSetMemberClassPermissions,
    secureRemoveMember,
    getAuditLogs
} from "../core/writePermissionLayer.js";
import { syncBroker } from "../core/syncBroker.js";

import {
    parseAiPromptOnServer,
    executeAiPlanOnServer,
    runAgentLoopOnServer,
    undoAiActionOnServer,
    redoAiActionOnServer,
    getAiBridgeState
} from "../core/aiBridge.js";

async function genJwtToken(fastify, user) {
    return await fastify.jwt.sign({
        id: user.id,
        username: user.name,
        email: user.email,
        isOrganizationAccount: Boolean(user.isOrganizationAccount)
    });
}

// Authentication helper
async function authenticate(request, reply) {
    try {
        if (request.query && request.query.token) {
            const decoded = request.server.jwt.verify(request.query.token);
            request.user = decoded;
            return decoded;
        }
        await request.jwtVerify();
        return request.user;
    } catch {
        reply.status(401).send({ error: 'Unauthorized', message: 'Token không hợp lệ hoặc đã hết hạn' });
        return null;
    }
}

// Organization auth helper (Ensures user is an Organization Account owner)
async function requireOrganization(request, reply) {
    const user = await authenticate(request, reply);
    if (!user) return null;

    const dbUser = await getUserById(user.id);
    if (!dbUser || !dbUser.isOrganizationAccount) {
        reply.status(403).send({ error: 'Forbidden', message: 'Chỉ tài khoản Tổ chức mới có quyền thực hiện thao tác này' });
        return null;
    }
    return dbUser;
}

export default async function (fastify) {
    // Web Views
    fastify.get('/', async (request, reply) => {
        return reply.view('index.ejs', {});
    });

    fastify.get('/signup', async (request, reply) => {
        return reply.view('signup.ejs', {});
    });

    fastify.get('/logout', async (request, reply) => {
        return reply.view('logout.ejs');
    });

    fastify.get('/login', async (request, reply) => {
        return reply.view('login.ejs');
    });

    fastify.get('/dashboard', async (request, reply) => {
        return reply.view('dashboard.ejs');
    });

    // Bắt buộc phải có classId sau /class-management/:classId
    fastify.get('/class-management', async (request, reply) => {
        return reply.redirect('/dashboard');
    });

    fastify.get('/class-management/:classId', async (request, reply) => {
        const { classId } = request.params;
        if (!classId || isNaN(Number(classId))) {
            return reply.redirect('/dashboard');
        }
        return reply.view('class-management.ejs');
    });

    // Auth API
    fastify.post('/submit-signup', async (request, reply) => {
        const { username, email, password, isOrganization } = request.body;

        if (!username || !email || !password || isOrganization === undefined) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Vui lòng điền đầy đủ thông tin' });
        }

        if (await isUserAlreadySignup(email)) {
            return reply.status(409).send({ error: 'Conflict', message: 'Email đã được đăng ký!' });
        }

        try {
            const user = await newUser(username, isOrganization, email, password);
            const token = await genJwtToken(fastify, user);
            return reply.status(200).send({ message: 'OK', token });
        } catch (e) {
            console.error(e);
            return reply.status(500).send({ error: 'Internal Server Error', message: 'Lỗi máy chủ nội bộ!' });
        }
    });

    fastify.post('/submit-login', async (request, reply) => {
        const { email, password } = request.body;
        if (!password || !email) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Vui lòng nhập Email và Mật khẩu' });
        }

        const verifyDat = await verifyLogin(email, password);

        if (verifyDat.status) {
            const token = await genJwtToken(fastify, verifyDat.user);
            return reply.status(200).send({ message: 'OK', token });
        }

        return reply.status(401).send({ error: 'Unauthorized', message: 'Email hoặc mật khẩu không chính xác' });
    });

    fastify.get('/api/me', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const dbUser = await getUserById(authUser.id);
        if (!dbUser) {
            return reply.status(444).send({ error: 'User Not Found' });
        }

        return reply.send({
            id: dbUser.id,
            name: dbUser.name,
            email: dbUser.email,
            isOrganizationAccount: Boolean(dbUser.isOrganizationAccount)
        });
    });

    // HIGH-PERFORMANCE COMBINED DASHBOARD ENDPOINT (All data in 1 single HTTP call)
    fastify.get('/api/organization/dashboard', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const dbUser = await getUserById(authUser.id);
        if (!dbUser) {
            return reply.status(404).send({ error: 'User Not Found' });
        }

        const user = {
            id: dbUser.id,
            name: dbUser.name,
            email: dbUser.email,
            isOrganizationAccount: Boolean(dbUser.isOrganizationAccount)
        };

        if (!user.isOrganizationAccount) {
            const [userOrganizations, classesList, yearsList] = await Promise.all([
                getUserOrganizations(dbUser.id),
                getAccessibleClassesForUser(user),
                getAccessibleAcademicYearsForUser(user)
            ]);

            return reply.send({
                user,
                userOrganizations,
                classes: classesList,
                academicYears: yearsList,
                members: [],
                aiState: { canUndo: false, canRedo: false },
                debugMode: process.env.DEBUG_MODE === 'true'
            });
        }

        const [classesList, yearsList, membersList] = await Promise.all([
            getClasses(dbUser.id),
            getAcademicYears(dbUser.id),
            getOrganizationMembers(dbUser.id)
        ]);

        const classesWithWrite = classesList.map(c => ({
            ...c,
            canWrite: true,
            organizationName: dbUser.name || "Tổ chức của bạn"
        }));

        const aiState = getAiBridgeState(dbUser.id);

        return reply.send({
            user,
            userOrganizations: [],
            classes: classesWithWrite,
            academicYears: yearsList,
            members: membersList,
            aiState,
            debugMode: process.env.DEBUG_MODE === 'true'
        });
    });

    // AUDIT LOGS ENDPOINT (Google Sheets Version History style)
    fastify.get('/api/organization/audit-logs', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { classId, limit } = request.query || {};

        try {
            const logs = await getAuditLogs(authUser, {
                classId: classId ? Number(classId) : null,
                limit: limit ? Number(limit) : 100
            });
            return reply.send({ auditLogs: logs });
        } catch (err) {
            return reply.status(400).send({ error: 'Bad Request', message: err.message });
        }
    });

    // Organization APIs
    fastify.get('/api/organization/classes', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const dbUser = await getUserById(authUser.id);
        if (!dbUser) return reply.status(404).send({ error: 'User Not Found' });

        const classesList = await getAccessibleClassesForUser(dbUser);
        return reply.send({ classes: classesList });
    });

    // Add Class: Secured by Write Permission Layer
    fastify.post('/api/organization/classes', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { name, academicYearId, academicYear } = request.body;
        if (!name || !name.trim()) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Tên lớp học không được để trống' });
        }

        try {
            const newCls = await secureCreateClass(authUser, { name: name.trim(), academicYearId: academicYearId || null, academicYear: academicYear || null }, "USER");
            return reply.send({ message: 'Thêm lớp học thành công', class: newCls });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    // Update Class: Secured by Write Permission Layer
    fastify.put('/api/organization/classes/:classId', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { classId } = request.params;
        const { name, academicYearId } = request.body;
        if (!name || !name.trim()) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Tên lớp học không được để trống' });
        }

        try {
            const updated = await secureUpdateClass(authUser, classId, { name: name.trim(), academicYearId: academicYearId || null }, "USER");
            return reply.send({ message: 'Cập nhật lớp học thành công', class: updated });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    // Delete Class: Secured by Write Permission Layer
    fastify.delete('/api/organization/classes/:classId', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { classId } = request.params;
        try {
            await secureDeleteClass(authUser, classId, "USER");
            return reply.send({ message: 'Xóa lớp học thành công' });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    fastify.get('/api/organization/academic-years', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const dbUser = await getUserById(authUser.id);
        if (!dbUser) return reply.status(404).send({ error: 'User Not Found' });

        const years = await getAccessibleAcademicYearsForUser(dbUser);
        return reply.send({ academicYears: years });
    });

    fastify.post('/api/organization/academic-years', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { name, startDate, endDate } = request.body;
        if (!name || !name.trim()) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Tên niên khóa không được để trống' });
        }

        try {
            const newYear = await secureCreateAcademicYear(authUser, { name: name.trim(), startDate: startDate || null, endDate: endDate || null }, "USER");
            return reply.send({ message: 'Thêm niên khóa thành công', academicYear: newYear });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    // Student Management APIs: Secured by Write Permission Layer & Audit Logging
    fastify.get('/api/organization/classes/:classId/students', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { classId } = request.params;
        const access = await checkUserClassAccess(authUser.id, classId);

        if (!access.canRead) {
            return reply.status(403).send({ error: 'Forbidden', message: 'Bạn không có quyền truy cập lớp học này' });
        }

        const students = await getStudentsByClass(access.organizationId, classId);
        return reply.send({
            students,
            userPermission: {
                canWrite: access.canWrite,
                isOwner: access.isOwner
            }
        });
    });

    // Atomic Batch Save Students: All-or-Nothing transaction for creates, updates, deletes
    fastify.post('/api/organization/classes/:classId/students/batch', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { classId } = request.params;
        const { creates = [], updates = [], deletes = [] } = request.body || {};

        try {
            const result = await secureBatchSaveStudents(authUser, classId, { creates, updates, deletes }, "USER");
            return reply.send({
                message: `Lưu đồng bộ thành công ${result.createdCount + result.updatedCount + result.deletedCount} học sinh`,
                result
            });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    // Real-time Multi-user SSE synchronization event stream
    fastify.get('/api/organization/sync-events', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { classId, orgId } = request.query || {};
        syncBroker.registerClient(request, reply, authUser, { classId, orgId });
    });

    fastify.post('/api/organization/students', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { classId, name, studentCode, dateOfBirth, phone, email, parentPhone, parentEmail, conductScore, conductDeductionReason } = request.body;

        if (!classId || !name || !name.trim()) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Vui lòng chọn Lớp học và nhập Tên học sinh' });
        }

        try {
            const student = await secureAddStudent(authUser, {
                classId,
                name: name.trim(),
                studentCode: studentCode ? studentCode.trim() : null,
                dateOfBirth,
                phone,
                email,
                parentPhone,
                parentEmail,
                conductScore,
                conductDeductionReason
            }, "USER");

            return reply.send({ message: 'Thêm học sinh thành công', student });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    fastify.put('/api/organization/students/:studentId', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { studentId } = request.params;

        try {
            const updated = await secureUpdateStudent(authUser, studentId, request.body, "USER");
            return reply.send({ message: 'Cập nhật học sinh thành công', student: updated });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    fastify.delete('/api/organization/students/:studentId', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { studentId } = request.params;

        try {
            await secureDeleteStudent(authUser, studentId, "USER");
            return reply.send({ message: 'Xóa học sinh thành công' });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    fastify.post('/api/organization/students/:studentId/deduct', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { studentId } = request.params;
        const { points, reason } = request.body || {};

        if (!points || Number(points) <= 0) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Vui lòng nhập số điểm trừ hợp lệ (lớn hơn 0)' });
        }

        try {
            const updated = await secureDeductConductScore(authUser, studentId, points, reason || 'Trừ điểm hạnh kiểm', "USER");
            return reply.send({ message: 'Trừ điểm hạnh kiểm thành công', student: updated });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    fastify.get('/api/organization/members', async (request, reply) => {
        const org = await requireOrganization(request, reply);
        if (!org) return;

        const members = await getOrganizationMembers(org.id);
        return reply.send({ members });
    });

    fastify.post('/api/organization/invite', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { email, permission } = request.body;
        if (!email || !email.trim()) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Vui lòng nhập email người được mời' });
        }

        try {
            const member = await secureInviteMember(authUser, { email: email.trim(), permission: permission || 'read' }, "USER");
            return reply.send({ message: 'Mời thành viên thành công', member });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    fastify.patch('/api/organization/members/:id/permission', async (request, reply) => {
        const org = await requireOrganization(request, reply);
        if (!org) return;

        const memberId = parseInt(request.params.id, 10);
        const { permission } = request.body;

        try {
            const updated = await updateMemberPermission(org.id, memberId, permission);
            return reply.send({ message: 'Cập nhật quyền thành công', member: updated });
        } catch (err) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Không thể cập nhật quyền' });
        }
    });

    // Update member's class-level write permissions
    fastify.post('/api/organization/members/:id/class-permissions', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const memberId = parseInt(request.params.id, 10);
        const { allowedClassIds } = request.body;

        try {
            const res = await secureSetMemberClassPermissions(authUser, memberId, allowedClassIds || [], "USER");
            return reply.send({ message: 'Cập nhật quyền ghi theo lớp thành công', permissions: res });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    fastify.delete('/api/organization/members/:id', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const memberId = parseInt(request.params.id, 10);

        try {
            await secureRemoveMember(authUser, memberId, "USER");
            return reply.send({ message: 'Đã xóa thành viên khỏi tổ chức' });
        } catch (err) {
            return reply.status(403).send({ error: 'Forbidden', message: err.message });
        }
    });

    // --- SERVER-SIDE AI BRIDGE ENDPOINTS ---

    // Helper to resolve Organization Context & Permissions for AI
    async function resolveTargetOrgForAi(authUser, classId = null) {
        const dbUser = await getUserById(authUser.id);
        if (!dbUser) throw new Error("User Not Found");

        if (dbUser.isOrganizationAccount) {
            return { targetOrgId: dbUser.id, canWrite: true, isOwner: true };
        }

        if (classId) {
            const access = await checkUserClassAccess(authUser.id, classId);
            if (!access.canWrite) {
                throw new Error("Bạn không có quyền thực hiện thao tác AI trên lớp học này");
            }
            return { targetOrgId: access.organizationId, canWrite: true, isOwner: false };
        }

        const accessibleClasses = await getAccessibleClassesForUser(dbUser);
        const writableClasses = accessibleClasses.filter(c => c.canWrite);
        if (writableClasses.length === 0) {
            throw new Error("Tài khoản cá nhân của bạn chưa được cấp quyền ghi ở lớp học nào");
        }
        return { targetOrgId: writableClasses[0].organizationId, canWrite: true, isOwner: false };
    }

    // 1. Parse natural language prompt on Server and return whitelisted dry-run preview plan
    fastify.post('/api/ai/parse-intent', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { prompt, classId, fileData } = request.body;
        try {
            const { targetOrgId } = await resolveTargetOrgForAi(authUser, classId);
            const [classList, yearList, studentList] = await Promise.all([
                getClasses(targetOrgId),
                getAcademicYears(targetOrgId),
                classId ? getStudentsByClass(targetOrgId, Number(classId)) : Promise.resolve([])
            ]);

            const currentClassObj = classId ? classList.find(c => Number(c.id) === Number(classId)) : null;

            const context = {
                currentClass: currentClassObj ? { id: currentClassObj.id, name: currentClassObj.name, academicYearId: currentClassObj.academicYearId } : null,
                currentStudents: (studentList || []).map(s => ({ id: s.id, studentCode: s.studentCode, name: s.name, conductScore: s.conductScore })),
                classes: classList.map(c => ({ id: c.id, name: c.name, academicYearId: c.academicYearId })),
                academicYears: yearList.map(y => ({ id: y.id, name: y.name }))
            };
            const result = await parseAiPromptOnServer(targetOrgId, prompt, context, fileData);
            return reply.send({
                ...result,
                debugMode: process.env.DEBUG_MODE === 'true'
            });
        } catch (err) {
            return reply.status(400).send({ error: 'Bad Request', message: err.message });
        }
    });

    // 2. Execute approved plan directly on Server via internal function calls (Run strictly under caller's permission)
    fastify.post('/api/ai/execute-plan', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { planActions, code, classId, prompt } = request.body || {};
        if (!Array.isArray(planActions) && (!code || typeof code !== 'string')) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Mã kịch bản JavaScript hoặc danh sách thao tác không hợp lệ' });
        }

        try {
            const { targetOrgId } = await resolveTargetOrgForAi(authUser, classId);
            const [classList, yearList, studentList] = await Promise.all([
                getClasses(targetOrgId),
                getAcademicYears(targetOrgId),
                classId ? getStudentsByClass(targetOrgId, Number(classId)) : Promise.resolve([])
            ]);

            const currentClassObj = classId ? classList.find(c => Number(c.id) === Number(classId)) : null;

            const context = {
                currentClass: currentClassObj ? { id: currentClassObj.id, name: currentClassObj.name, academicYearId: currentClassObj.academicYearId } : null,
                currentStudents: (studentList || []).map(s => ({ id: s.id, studentCode: s.studentCode, name: s.name, conductScore: s.conductScore })),
                classes: classList.map(c => ({ id: c.id, name: c.name, academicYearId: c.academicYearId })),
                academicYears: yearList.map(y => ({ id: y.id, name: y.name }))
            };

            // Execute AI script strictly under caller's permission & writePermissionLayer, reflecting execution results to Agent
            const res = await executeAiPlanOnServer(authUser, targetOrgId, planActions, code, context, prompt);
            
            syncBroker.broadcastSyncEvent({
                orgId: targetOrgId,
                classId: classId ? Number(classId) : null,
                type: 'AI_MUTATION',
                senderUserId: authUser.id,
                message: 'AI Agent vừa thực thi thay đổi trên hệ thống.'
            });

            return reply.send(res);
        } catch (err) {
            return reply.status(400).send({ error: 'Server Permission Error', message: err.message });
        }
    });

    // 2.1. Autonomous ReAct Agent Loop: Agent reasons, runs commands, receives results, and reflects
    fastify.post('/api/ai/agent-loop', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { prompt, classId, fileData, maxTurns } = request.body || {};
        if (!prompt || !prompt.trim()) {
            return reply.status(400).send({ error: 'Bad Request', message: 'Vui lòng nhập câu lệnh cho Agent' });
        }

        try {
            const { targetOrgId } = await resolveTargetOrgForAi(authUser, classId);
            const [classList, yearList, studentList] = await Promise.all([
                getClasses(targetOrgId),
                getAcademicYears(targetOrgId),
                classId ? getStudentsByClass(targetOrgId, Number(classId)) : Promise.resolve([])
            ]);

            const currentClassObj = classId ? classList.find(c => Number(c.id) === Number(classId)) : null;

            const context = {
                currentClass: currentClassObj ? { id: currentClassObj.id, name: currentClassObj.name, academicYearId: currentClassObj.academicYearId } : null,
                currentStudents: (studentList || []).map(s => ({ id: s.id, studentCode: s.studentCode, name: s.name, conductScore: s.conductScore })),
                classes: classList.map(c => ({ id: c.id, name: c.name, academicYearId: c.academicYearId })),
                academicYears: yearList.map(y => ({ id: y.id, name: y.name }))
            };

            const res = await runAgentLoopOnServer(authUser, targetOrgId, prompt, context, fileData, maxTurns || 3);

            syncBroker.broadcastSyncEvent({
                orgId: targetOrgId,
                classId: classId ? Number(classId) : null,
                type: 'AI_MUTATION',
                senderUserId: authUser.id,
                message: 'AI Agent vừa thực thi thay đổi trên hệ thống.'
            });

            return reply.send(res);
        } catch (err) {
            return reply.status(400).send({ error: 'Agent Execution Error', message: err.message });
        }
    });

    // 3. Undo last action directly on Server
    fastify.post('/api/ai/undo', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { classId } = request.body || {};
        try {
            const { targetOrgId } = await resolveTargetOrgForAi(authUser, classId);
            const res = await undoAiActionOnServer(targetOrgId);

            syncBroker.broadcastSyncEvent({
                orgId: targetOrgId,
                classId: classId ? Number(classId) : null,
                type: 'AI_MUTATION',
                senderUserId: authUser.id,
                message: 'Thao tác AI vừa được hoàn tác.'
            });

            return reply.send(res);
        } catch (err) {
            return reply.status(400).send({ error: 'Undo Error', message: err.message });
        }
    });

    // 4. Redo last undone action directly on Server
    fastify.post('/api/ai/redo', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        const { classId } = request.body || {};
        try {
            const { targetOrgId } = await resolveTargetOrgForAi(authUser, classId);
            const res = await redoAiActionOnServer(targetOrgId);

            syncBroker.broadcastSyncEvent({
                orgId: targetOrgId,
                classId: classId ? Number(classId) : null,
                type: 'AI_MUTATION',
                senderUserId: authUser.id,
                message: 'Thao tác AI vừa được làm lại.'
            });

            return reply.send(res);
        } catch (err) {
            return reply.status(400).send({ error: 'Redo Error', message: err.message });
        }
    });

    // 5. Get current AI Bridge state (canUndo, canRedo) on Server
    fastify.get('/api/ai/state', async (request, reply) => {
        const authUser = await authenticate(request, reply);
        if (!authUser) return;

        try {
            const { targetOrgId } = await resolveTargetOrgForAi(authUser);
            const state = getAiBridgeState(targetOrgId);
            return reply.send(state);
        } catch {
            return reply.send({ canUndo: false, canRedo: false });
        }
    });
}