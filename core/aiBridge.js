import { GoogleGenAI } from '@google/genai';
import 'dotenv/config';
import {
    secureCreateClass,
    secureDeleteClass,
    secureCreateAcademicYear,
    secureDeleteAcademicYear,
    secureAddStudent,
    secureUpdateStudent,
    secureDeleteStudent,
    secureDeductConductScore,
    secureInviteMember
} from './writePermissionLayer.js';
import {
    deleteClass,
    deleteStudent,
    addStudentToClass,
    deleteAcademicYear,
    removeOrganizationMember,
    getClasses,
    getStudentsByClass,
    getAcademicYears
} from './organization.js';

import ivm from 'isolated-vm';

/**
 * Server-side AI Bridge Layer powered by Google Gemini API
 * 
 * Functions as the secure intermediate interpreter between Gemini AI model and internal Server APIs.
 * Runs strictly on the Node.js server to interpret intents, enforce security whitelists,
 * generate dry-run previews, execute server routines directly, and manage Undo/Redo stacks.
 */

// In-memory Undo/Redo stacks keyed by Organization ID
const orgHistoryStacks = new Map(); // orgId -> array of executed batches
const orgRedoStacks = new Map();    // orgId -> array of undone batches

function getOrgHistory(orgId) {
    if (!orgHistoryStacks.has(orgId)) orgHistoryStacks.set(orgId, []);
    return orgHistoryStacks.get(orgId);
}

function getOrgRedo(orgId) {
    if (!orgRedoStacks.has(orgId)) orgRedoStacks.set(orgId, []);
    return orgRedoStacks.get(orgId);
}

/**
 * SERVER SECURITY WHITELIST:
 * Only explicitly approved server-side functions are registered here.
 * Executes strictly under acting user permissions with source = "AGENT".
 */
const WHITELISTED_SERVER_ACTIONS = {
    'create_class': async (actorUser, orgId, params) => {
        return await secureCreateClass(actorUser, params, 'AGENT');
    },
    'delete_class': async (actorUser, orgId, params) => {
        return await secureDeleteClass(actorUser, params.classId, 'AGENT');
    },
    'get_classes': async (actorUser, orgId) => {
        return await getClasses(orgId);
    },
    'get_students': async (actorUser, orgId, params) => {
        return await getStudentsByClass(orgId, params.classId);
    },
    'get_academic_years': async (actorUser, orgId) => {
        return await getAcademicYears(orgId);
    },
    'create_academic_year': async (actorUser, orgId, params) => {
        return await secureCreateAcademicYear(actorUser, params, 'AGENT');
    },
    'delete_academic_year': async (actorUser, orgId, params) => {
        return await secureDeleteAcademicYear(actorUser, params.academicYearId, 'AGENT');
    },
    'invite_member': async (actorUser, orgId, params) => {
        return await secureInviteMember(actorUser, params, 'AGENT');
    },
    'add_student': async (actorUser, orgId, params) => {
        return await secureAddStudent(actorUser, params, 'AGENT');
    },
    'update_student': async (actorUser, orgId, params) => {
        return await secureUpdateStudent(actorUser, params.studentId, params, 'AGENT');
    },
    'delete_student': async (actorUser, orgId, params) => {
        return await secureDeleteStudent(actorUser, params.studentId, 'AGENT');
    },
    'deduct_conduct_score': async (actorUser, orgId, params) => {
        return await secureDeductConductScore(actorUser, params.studentId, params.points, params.reason, 'AGENT');
    }
};


/**
 * SERVER REVERSAL HANDLERS FOR UNDO
 */
const SERVER_REVERSAL_HANDLERS = {
    'create_class': async (orgId, params, result) => {
        if (result && result.id) {
            await deleteClass(orgId, result.id);
            console.log(`[Server AI Bridge Revert] Deleted class #${result.id} (${result.name})`);
        }
    },
    'create_academic_year': async (orgId, params, result) => {
        if (result && result.id) {
            await deleteAcademicYear(orgId, result.id);
            console.log(`[Server AI Bridge Revert] Deleted academic year #${result.id} (${result.name})`);
        }
    },
    'invite_member': async (orgId, params, result) => {
        if (result && result.id) {
            await removeOrganizationMember(orgId, result.id);
            console.log(`[Server AI Bridge Revert] Removed invited member #${result.id}`);
        }
    },
    'add_student': async (orgId, params, result) => {
        if (result && result.id) {
            await deleteStudent(orgId, result.id);
            console.log(`[Server AI Bridge Revert] Deleted student #${result.id} (${result.name})`);
        }
    },
    'delete_student': async (orgId, params, result) => {
        if (result && result.classId) {
            await addStudentToClass(orgId, result);
            console.log(`[Server AI Bridge Revert] Restored deleted student #${result.id} (${result.name})`);
        }
    }
};

/**
 * Call Google Gemini API to parse intent into structured actions with Agent Thought Process & Execution Feedback
 */
async function callGeminiApi(prompt, context = {}, fileData = null, executionFeedback = null) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return null;

    try {
        const ai = new GoogleGenAI({ apiKey });
        const systemInstruction = `Bạn là trợ lý AI thông minh kiêm Agent quản lý ứng dụng EduManager cho Tổ chức.
Nhiệm vụ của bạn là đọc yêu cầu của người dùng, SUY NGHĨ (THOUGHT) phân tích dữ liệu kỹ lưỡng, và tạo ra mã JavaScript (async code) tối ưu để thực thi trực tiếp trên Server trong V8 Isolate Sandbox (isolated-vm).
Nếu nhận được kết quả thực thi lệnh trước đó (Execution Feedback), bạn PHẢI phân tích kết quả đó để tiếp tục suy nghĩ và hoàn thành mục tiêu.

QUY TẮC PHẠM VI DỮ LIỆU & QUYỀN HẠN (CRITICAL CONTEXT CONSTRAINTS):
1. ƯU TIÊN VÀ CHỈ TÁC ĐỘNG LÊN MÀN HÌNH HIỆN TẠI NẾU KHÔNG CÓ YÊU CẦU KHÁC:
   - Trong context được truyền vào có thông tin: currentClass (màn hình lớp học hiện tại người dùng đang xem) và currentStudents (danh sách học sinh thuộc lớp học hiện tại cùng ID và Tên).
   - Nếu người dùng đưa ra câu lệnh thao tác học sinh (ví dụ: "trừ điểm Nguyễn Văn A", "thêm học sinh mới", "cập nhật học sinh"), BẠN PHẢI ƯU TIÊN TÌM HỌC SINH VÀ LỚP HỌC TRONG currentClass VÀ currentStudents CỦA MÀN HÌNH HIỆN TẠI TRƯỚC TIÊN.
   - TUYỆT ĐỐI KHÔNG CHỈNH SỬA, KHÔNG XÓA VÀ KHÔNG TRỪ ĐIỂM HỌC SINH HOẶC LỚP HỌC KHÔNG LIÊN QUAN ở màn hình khác trừ khi người dùng chỉ định rõ ràng tên lớp học khác hoặc niên khóa khác.

2. QUY TẮC THAO TÁC MÃ JAVASCRIPT:
   - Sử dụng vòng lặp (for, for...of, forEach) khi thao tác hàng loạt.
   - Kiểm tra điều kiện (if/else) trước khi gọi hàm.
   - Luôn sử dụng đúng ID học sinh (studentId) và ID lớp (classId) dựa vào danh sách currentStudents và classes có trong Context.
   - Có thể dùng console.log() để ghi lại thông tin tiến trình thực thi, hoặc dùng lệnh return để trả về kết quả cho Agent nhận diện.

DANH SÁCH KIỂU DỮ LIỆU (TYPES & INTERFACES):
- StudentInput: {
    name: string;           // (Bắt buộc) Họ và tên học sinh
    studentCode?: string;   // (Tùy chọn) Mã học sinh, ví dụ "HS001"
    dateOfBirth?: string;   // (Tùy chọn) Ngày sinh định dạng "YYYY-MM-DD"
    phone?: string;         // (Tùy chọn) Số điện thoại học sinh
    email?: string;         // (Tùy chọn) Email học sinh
    parentPhone?: string;   // (Tùy chọn) Số điện thoại phụ huynh
    parentEmail?: string;   // (Tùy chọn) Email phụ huynh
    conductScore?: number;  // (Tùy chọn) Điểm hạnh kiểm (0 - 100, mặc định 100)
    conductDeductionReason?: string; // (Tùy chọn) Lý do trừ điểm hạnh kiểm (nếu bị trừ điểm)
  }

- StudentUpdateInput: {
    name?: string;          // (Tùy chọn) Họ và tên mới
    studentCode?: string;   // (Tùy chọn) Mã học sinh mới
    dateOfBirth?: string;   // (Tùy chọn) Ngày sinh mới
    phone?: string;         // (Tùy chọn) SĐT mới
    email?: string;         // (Tùy chọn) Email mới
    parentPhone?: string;   // (Tùy chọn) SĐT phụ huynh mới
    parentEmail?: string;   // (Tùy chọn) Email phụ huynh mới
    conductScore?: number;  // (Tùy chọn) Điểm hạnh kiểm mới (0 - 100)
    conductDeductionReason?: string; // (Tùy chọn) Lý do trừ điểm hạnh kiểm mới
  }

DANH SÁCH HÀM API SERVER & CÚ PHÁP (SERVER API SIGNATURES):
1. await createClass(name: string, academicYearIdOrName?: number | string): Promise<{ id: number, name: string }>
   -> Tạo lớp học mới. Ví dụ: await createClass("10A1", 1) hoặc await createClass("10A1", "2024 - 2025")

2. await deleteClass(classId: number): Promise<{ id: number }>
   -> Xóa lớp học theo classId (number). Ví dụ: await deleteClass(1)

3. await getClasses(): Promise<Array<{ id: number, name: string, academicYearId: number | null }>>
   -> Lấy danh sách tất cả các lớp học hiện có của Tổ chức. Ví dụ: const classes = await getClasses()

4. await getStudents(classId?: number): Promise<Array<{ id: number, studentCode: string, name: string, conductScore: number }>>
   -> Lấy danh sách tất cả học sinh thuộc lớp classId (hoặc tất cả học sinh nếu không truyền classId).

5. await createAcademicYear(name: string, startDate?: string, endDate?: string): Promise<{ id: number, name: string }>
   -> Tạo đợt niên khóa mới. Ví dụ: await createAcademicYear("2024 - 2025", "2024-09-01", "2025-05-31")

6. await deleteAcademicYear(academicYearId: number): Promise<{ id: number }>
   -> Xóa niên khóa theo academicYearId (number). Ví dụ: await deleteAcademicYear(1)

7. await getAcademicYears(): Promise<Array<{ id: number, name: string, startDate: string, endDate: string }>>
   -> Lấy danh sách các đợt niên khóa của Tổ chức. Ví dụ: const years = await getAcademicYears()

8. await inviteMember(email: string, permission?: "read" | "write"): Promise<{ id: number, email: string }>
   -> Mời thành viên mới vào tổ chức qua email. Ví dụ: await inviteMember("user@example.com", "read")

9. await addStudent(classId: number, studentData: StudentInput): Promise<{ id: number, name: string, classId: number }>
   -> Thêm học sinh mới vào lớp. Ví dụ: await addStudent(currentClass?.id || 1, { name: "Nguyễn Văn A", conductScore: 100 })
   QUY TẮC BẮT BUỘC VỀ classId:
   - Nếu đang ở màn hình lớp học (currentClass tồn tại): LUÔN sử dụng currentClass.id (ví dụ: await addStudent(currentClass.id, { name: "Nguyễn Văn A" })).
   - Nếu ở Dashboard: tìm ID lớp tương ứng trong danh sách classes theo tên lớp (ví dụ: const target = classes.find(c => c.name.toLowerCase() === "10a1".toLowerCase()); if (target) await addStudent(target.id, { name: "Nguyễn Văn A" });).
   - TUYỆT ĐỐI KHÔNG truyền undefined hoặc null cho classId.

10. await updateStudent(studentId: number, updateData: StudentUpdateInput): Promise<{ id: number, name: string }>
    -> Cập nhật thông tin học sinh theo studentId. Ví dụ: await updateStudent(10, { conductScore: 95 })

11. await deleteStudent(studentId: number): Promise<{ id: number }>
    -> Xóa học sinh theo studentId (number). Ví dụ: await deleteStudent(10)

12. await deductConductScore(studentId: number, points: number, reason: string): Promise<{ id: number, name: string, conductScore: number }>
    -> Trừ điểm hạnh kiểm của học sinh kèm lý do. Ví dụ: await deductConductScore(10, 5, "Đi học muộn")

YÊU CẦU ĐỊNH DẠNG JSON TRẢ VỀ (JSON OUTPUT SCHEMA):
1. "thought": Luồng tư duy / suy nghĩ của Agent: Phân tích kỹ yêu cầu của người dùng, phân tích dữ liệu trong context, suy nghĩ về kết quả thực thi lệnh trước đó (nếu có), logic lựa chọn hàm API, các bước dự kiến và cách xử lý trường hợp đặc biệt.
2. "summary": Tóm tắt ngắn gọn 1 câu mục tiêu hoặc kết quả của thao tác.
3. "reply": Phản hồi trò chuyện bằng tiếng Việt thân thiện, giải thích rõ ràng thao tác sẽ thực hiện hoặc tổng kết kết quả.
4. "code": Đoạn mã JavaScript hợp lệ (thuần mã JS, KHÔNG chứa markdown block \`\`\`js) xử lý logic, có thể trống ("") nếu đã hoàn thành và không cần thực thi thêm mã nào.
`;

        const parts = [{ text: `Câu lệnh người dùng: "${prompt}"\nBối cảnh dữ liệu hiện tại: ${JSON.stringify(context)}` }];
        if (fileData && fileData.data && fileData.mimeType) {
            parts.push({
                inlineData: {
                    data: fileData.data,
                    mimeType: fileData.mimeType
                }
            });
        }

        if (executionFeedback) {
            parts.push({
                text: `KẾT QUẢ THỰC THI LỆNH TRÊN SERVER (V8 Sandbox):\n` +
                      `- Trạng thái: ${executionFeedback.success ? 'THÀNH CÔNG' : 'THẤT BẠI'}\n` +
                      `- Logs (console.log): ${JSON.stringify(executionFeedback.logs || [])}\n` +
                      `- Giá trị trả về (Result): ${JSON.stringify(executionFeedback.result !== undefined ? executionFeedback.result : null)}\n` +
                      `- Các thay đổi Database đã ghi nhận: ${JSON.stringify(executionFeedback.executedBatch || [])}\n` +
                      (executionFeedback.error ? `- Lỗi: ${executionFeedback.error}\n` : '') +
                      `Hãy suy nghĩ (thought) và đánh giá kết quả thực thi này so với yêu cầu ban đầu của người dùng.`
            });
        }

        const response = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: [
                { role: 'user', parts: parts }
            ],
            config: {
                systemInstruction,
                responseMimeType: 'application/json'
            }
        });

        if (response && response.text) {
            const parsed = JSON.parse(response.text);
            return parsed;
        }
    } catch (err) {
        console.error('[Gemini API Call Exception]', err.message);
    }
    return null;
}

/**
 * Agent Post-Execution Reflection:
 * Feeds actual execution outputs (logs, returned values, database modifications, errors)
 * back to Gemini so the Agent can think and evaluate the results of its commands.
 */
export async function generateAgentExecutionFeedback(prompt, code, executionOutput, context = {}) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        return {
            thought: `Đã hoàn tất thực thi ${executionOutput.executedBatch?.length || 0} tác vụ trên hệ thống.`,
            reply: executionOutput.success
                ? `Đã thực thi thành công ${executionOutput.executedBatch?.length || 0} thao tác.`
                : `Thực thi gặp lỗi: ${executionOutput.error || 'Lỗi không xác định'}`
        };
    }

    try {
        const ai = new GoogleGenAI({ apiKey });
        const systemInstruction = `Bạn là trợ lý AI thông minh kiêm Agent quản lý ứng dụng EduManager.
Bạn vừa nhận được kết quả thực thi lệnh thực tế trên Server (V8 sandbox).
Nhiệm vụ của bạn là đọc kết quả thực tế này, SUY NGHĨ (THOUGHT) đánh giá xem các thao tác đã hoàn thành như thế nào so với yêu cầu ban đầu của người dùng, và đưa ra phản hồi tổng kết ngắn gọn, chính xác bằng tiếng Việt (reply).

YÊU CẦU ĐỊNH DẠNG JSON TRẢ VỀ:
{
  "thought": "Luồng suy nghĩ của Agent khi nhận kết quả: phân tích xem mục tiêu ban đầu đã hoàn thành chưa, đánh giá các bản ghi đã tạo/sửa/xóa và các log output ghi nhận được...",
  "reply": "Phản hồi kết quả cụ thể, rõ ràng cho người dùng (ví dụ: đã tạo học sinh ID bao nhiêu, lớp nào, có điểm gì cần chú ý...)"
}`;

        const promptText = `Yêu cầu ban đầu của người dùng: "${prompt || 'Thực thi kịch bản'}"
Mã JS đã chạy:
${code || '(Thực thi từ danh sách thao tác)'}

KẾT QUẢ THỰC THI TRÊN SERVER:
- Trạng thái: ${executionOutput.success ? 'THÀNH CÔNG' : 'THẤT BẠI'}
- Logs (console.log): ${JSON.stringify(executionOutput.logs || [])}
- Giá trị trả về (Result): ${JSON.stringify(executionOutput.result !== undefined ? executionOutput.result : null)}
- Các bản ghi thay đổi trong CSDL: ${JSON.stringify(executionOutput.executedBatch || [])}
${executionOutput.error ? `- Lỗi phát sinh: ${executionOutput.error}` : ''}
`;

        const response = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: [{ role: 'user', parts: [{ text: promptText }] }],
            config: {
                systemInstruction,
                responseMimeType: 'application/json'
            }
        });

        if (response && response.text) {
            const parsed = JSON.parse(response.text);
            return parsed;
        }
    } catch (err) {
        console.error('[Gemini Feedback Exception]', err.message);
    }

    return {
        thought: `Đã hoàn tất xử lý ${executionOutput.executedBatch?.length || 0} thao tác trên server.`,
        reply: executionOutput.success
            ? `Thực thi thành công ${executionOutput.executedBatch?.length || 0} thao tác.`
            : `Thực thi gặp lỗi: ${executionOutput.error || 'Lỗi không xác định'}`
    };
}

/**
 * Rule-based Intent Parser Fallback (Used if Gemini API key is not configured or offline)
 */
function parseIntentFallback(prompt) {
    const lower = prompt.toLowerCase();
    const plan = [];

    // Detect Academic Year creation
    const yearMatches = prompt.match(/(?:tạo|thêm|mới)\s+niên\s+khóa\s+([0-9]{4}\s*[-–]\s*[0-9]{4})/gi);
    if (yearMatches) {
        for (const match of yearMatches) {
            const yearName = match.replace(/(?:tạo|thêm|mới)\s+niên\s+khóa\s+/i, '').trim();
            plan.push({
                action: 'create_academic_year',
                params: { name: yearName },
                description: `Tạo niên khóa mới: ${yearName}`
            });
        }
    }

    // Detect Class creation
    const classMatches = prompt.match(/(?:tạo|thêm)\s+(?:các\s+)?lớp\s+([a-zA-Z0-9,\s]+)/gi);
    if (classMatches) {
        for (const match of classMatches) {
            const namesStr = match.replace(/(?:tạo|thêm)\s+(?:các\s+)?lớp\s+/i, '').trim();
            const classNames = namesStr.split(/[,;\s]+/).filter(n => n.length >= 2);
            for (const className of classNames) {
                if (!plan.some(p => p.action === 'create_class' && p.params.name === className)) {
                    plan.push({
                        action: 'create_class',
                        params: { name: className },
                        description: `Tạo lớp học mới: ${className}`
                    });
                }
            }
        }
    }

    // Detect Invite member
    const emailMatches = prompt.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi);
    if (emailMatches) {
        for (const email of emailMatches) {
            plan.push({
                action: 'invite_member',
                params: { email: email, permission: 'read' },
                description: `Mời thành viên mới: ${email}`
            });
        }
    }

    // Fallback for standalone class code (e.g., "lớp 12A1")
    if (plan.length === 0 && lower.includes('lớp')) {
        const words = prompt.split(/\s+/);
        const classWord = words.find(w => /^[0-9]{1,2}[a-zA-Z][0-9]?$/i.test(w));
        if (classWord) {
            plan.push({
                action: 'create_class',
                params: { name: classWord.toUpperCase() },
                description: `Tạo lớp học mới: ${classWord.toUpperCase()}`
            });
        }
    }

    const thought = plan.length > 0
        ? `Đã phân tích yêu cầu dựa trên quy tắc từ khóa (Fallback Mode). Dự kiến thực hiện ${plan.length} thao tác.`
        : `Chưa nhận diện được hành động cụ thể từ câu lệnh. Đang ở chế độ hướng dẫn người dùng.`;

    return {
        thought,
        reply: plan.length > 0
            ? `Tôi đã nhận lệnh và phân tích kế hoạch gồm ${plan.length} thao tác.`
            : `Xin chào! Tôi là AI Assistant của EduManager. Bạn có thể yêu cầu tôi tạo lớp học, niên khóa hoặc mời thành viên.`,
        summary: plan.length > 0
            ? `Phân tích thành công ${plan.length} thao tác được phép`
            : 'Không tìm thấy thao tác tạo dữ liệu trong câu lệnh',
        plan
    };
}

/**
 * 1. Server-side Intent Interpreter: Integrates Gemini API to generate JS Code with Whitelist Security
 */
export async function parseAiPromptOnServer(orgId, prompt, context = {}, fileData = null) {
    if (!prompt || !prompt.trim()) {
        throw new Error('Vui lòng nhập câu lệnh');
    }

    // Try Gemini API first
    let geminiRes = await callGeminiApi(prompt, context, fileData);
    let reply = '';
    let thought = '';
    let summary = '';
    let code = '';
    let rawPlan = [];

    if (geminiRes) {
        thought = geminiRes.thought || 'Đã phân tích logic câu lệnh dựa trên bối cảnh hiện tại.';
        reply = geminiRes.reply || 'Đã tạo đoạn mã JavaScript thực thi.';
        summary = geminiRes.summary || 'Kịch bản thực thi JS do AI tạo';
        code = geminiRes.code || '';

        // Also support fallback plan if Gemini returns plan array instead of code
        if (Array.isArray(geminiRes.plan)) {
            rawPlan = geminiRes.plan.map(p => ({
                action: p.action,
                params: p.params || p,
                description: p.description || `${p.action}: ${JSON.stringify(p.params || p)}`
            }));
        }
    } else {
        // Fallback to Rule-based Parser if Gemini API key is missing or errored
        const fallbackRes = parseIntentFallback(prompt);
        thought = fallbackRes.thought;
        reply = fallbackRes.reply;
        summary = fallbackRes.summary;
        rawPlan = fallbackRes.plan;

        // Generate JS code from fallback plan
        code = rawPlan.map(item => {
            if (item.action === 'create_academic_year') {
                return `await createAcademicYear("${item.params.name}");`;
            } else if (item.action === 'create_class') {
                return `await createClass("${item.params.name}");`;
            } else if (item.action === 'invite_member') {
                return `await inviteMember("${item.params.email}");`;
            }
            return '';
        }).filter(Boolean).join('\n');
    }

    // STRICT SECURITY SANITIZATION: Filter all plan items against server whitelist
    const safePlan = rawPlan.filter(item => WHITELISTED_SERVER_ACTIONS[item.action]);

    return {
        thought,
        reply,
        summary,
        code,
        actions: safePlan,
        isGeminiPowered: Boolean(process.env.GEMINI_API_KEY && geminiRes)
    };
}

/**
 * 2. Execute Approved JavaScript Code or Plan directly on Server in a Whitelisted Context
 */
export async function executeAiPlanOnServer(actorUser, orgId, planActions, codeScript = null, screenContext = {}, userPrompt = null) {
    const history = getOrgHistory(orgId);
    const redoStack = getOrgRedo(orgId);
    const executedBatch = [];
    const executionLogs = [];
    let executionResult = undefined;
    const safeContext = (screenContext && typeof screenContext === 'object') ? screenContext : {};

    // If JavaScript code script is provided, execute JS script on server with bound Whitelisted server APIs
    if (codeScript && typeof codeScript === 'string' && codeScript.trim()) {
        const cleanScript = codeScript
            .replace(/```javascript/gi, '')
            .replace(/```js/gi, '')
            .replace(/```/g, '')
            .trim();

        // Ultra-secure V8 sandbox execution using isolated-vm
        const isolate = new ivm.Isolate({ memoryLimit: 128 });
        const v8Context = await isolate.createContext();
        const jail = v8Context.global;

        await jail.set('context', new ivm.ExternalCopy(safeContext).copyInto());
        await jail.set('currentClass', new ivm.ExternalCopy(safeContext.currentClass || null).copyInto());
        await jail.set('currentStudents', new ivm.ExternalCopy(safeContext.currentStudents || []).copyInto());
        await jail.set('classes', new ivm.ExternalCopy(safeContext.classes || []).copyInto());
        await jail.set('academicYears', new ivm.ExternalCopy(safeContext.academicYears || []).copyInto());

        // Safe wrapper for host APIs crossing isolated-vm boundary:
        // Catches any host errors and returns { ok: false, error: err.message }, preventing unhandled promise rejections on the host.
        const wrapSafeApi = (fn) => {
            return new ivm.Reference(async (...args) => {
                try {
                    const res = await fn(...args);
                    return new ivm.ExternalCopy({ ok: true, data: res }).copyInto();
                } catch (err) {
                    return new ivm.ExternalCopy({ ok: false, error: err.message || String(err) }).copyInto();
                }
            });
        };

        // Bind ReferenceFunctions for Whitelisted APIs
        await jail.set('_createClass', wrapSafeApi(async (name, academicYearIdOrName) => {
            let yearId = null;
            let yearName = null;
            if (typeof academicYearIdOrName === 'number') yearId = academicYearIdOrName;
            else if (typeof academicYearIdOrName === 'string') yearName = academicYearIdOrName;

            const res = await WHITELISTED_SERVER_ACTIONS['create_class'](actorUser, orgId, { name, academicYearId: yearId, academicYear: yearName });
            executedBatch.push({ action: 'create_class', params: { name, academicYearId: yearId, academicYear: yearName }, result: res });
            return res;
        }));

        await jail.set('_deleteClass', wrapSafeApi(async (classIdOrName) => {
            let targetClassId = classIdOrName;
            if (typeof classIdOrName === 'object' && classIdOrName !== null) {
                targetClassId = classIdOrName.id || classIdOrName.classId;
            }
            if (typeof targetClassId === 'string' && isNaN(Number(targetClassId))) {
                const found = (safeContext.classes || []).find(c => c.name && c.name.toLowerCase() === targetClassId.trim().toLowerCase());
                if (found) targetClassId = found.id;
            }
            const resolvedClassId = Number(targetClassId);
            if (isNaN(resolvedClassId) || !resolvedClassId) {
                throw new Error("Không xác định được ID lớp học để xóa.");
            }
            const params = { classId: resolvedClassId };
            const res = await WHITELISTED_SERVER_ACTIONS['delete_class'](actorUser, orgId, params);
            executedBatch.push({ action: 'delete_class', params, result: res });
            return res;
        }));

        await jail.set('_getClasses', wrapSafeApi(async () => {
            const res = await WHITELISTED_SERVER_ACTIONS['get_classes'](actorUser, orgId);
            return res;
        }));

        await jail.set('_getStudents', wrapSafeApi(async (classIdOrName) => {
            let targetClassId = classIdOrName;
            if (typeof classIdOrName === 'object' && classIdOrName !== null) {
                targetClassId = classIdOrName.id || classIdOrName.classId;
            }
            if (typeof targetClassId === 'string' && isNaN(Number(targetClassId))) {
                const found = (safeContext.classes || []).find(c => c.name && c.name.toLowerCase() === targetClassId.trim().toLowerCase());
                if (found) targetClassId = found.id;
            }
            const resolvedClassId = Number(targetClassId);
            const params = (!isNaN(resolvedClassId) && resolvedClassId) ? { classId: resolvedClassId } : {};
            const res = await WHITELISTED_SERVER_ACTIONS['get_students'](actorUser, orgId, params);
            return res;
        }));

        await jail.set('_getAcademicYears', wrapSafeApi(async () => {
            const res = await WHITELISTED_SERVER_ACTIONS['get_academic_years'](actorUser, orgId);
            return res;
        }));

        await jail.set('_createAcademicYear', wrapSafeApi(async (name, startDate, endDate) => {
            const res = await WHITELISTED_SERVER_ACTIONS['create_academic_year'](actorUser, orgId, { name, startDate, endDate });
            executedBatch.push({ action: 'create_academic_year', params: { name }, result: res });
            return res;
        }));

        await jail.set('_deleteAcademicYear', wrapSafeApi(async (academicYearId) => {
            let targetYearId = academicYearId;
            if (typeof academicYearId === 'object' && academicYearId !== null) {
                targetYearId = academicYearId.id || academicYearId.academicYearId;
            }
            const resolvedYearId = Number(targetYearId);
            if (isNaN(resolvedYearId) || !resolvedYearId) {
                throw new Error("Không xác định được ID niên khóa để xóa.");
            }
            const params = { academicYearId: resolvedYearId };
            const res = await WHITELISTED_SERVER_ACTIONS['delete_academic_year'](actorUser, orgId, params);
            executedBatch.push({ action: 'delete_academic_year', params, result: res });
            return res;
        }));

        await jail.set('_inviteMember', wrapSafeApi(async (email, permission = 'read') => {
            const res = await WHITELISTED_SERVER_ACTIONS['invite_member'](actorUser, orgId, { email, permission });
            executedBatch.push({ action: 'invite_member', params: { email, permission }, result: res });
            return res;
        }));

        await jail.set('_addStudent', wrapSafeApi(async (classIdOrObj, studentObj) => {
            let targetClassId = classIdOrObj;
            let studentData = studentObj;

            // Handle single-argument call: addStudent({ name: "...", classId: 1 })
            if (typeof classIdOrObj === 'object' && classIdOrObj !== null) {
                studentData = classIdOrObj;
                targetClassId = studentData.classId;
            }

            // If targetClassId is class name string like "10A1", resolve by name from safeContext.classes
            if (typeof targetClassId === 'string' && isNaN(Number(targetClassId))) {
                const found = (safeContext.classes || []).find(c => c.name && c.name.toLowerCase() === targetClassId.trim().toLowerCase());
                if (found) targetClassId = found.id;
            }

            let resolvedClassId = Number(targetClassId);
            if (isNaN(resolvedClassId) || !resolvedClassId) {
                if (studentData && studentData.classId && !isNaN(Number(studentData.classId))) {
                    resolvedClassId = Number(studentData.classId);
                } else if (safeContext.currentClass && safeContext.currentClass.id && !isNaN(Number(safeContext.currentClass.id))) {
                    resolvedClassId = Number(safeContext.currentClass.id);
                } else if (Array.isArray(safeContext.classes) && safeContext.classes.length === 1) {
                    resolvedClassId = Number(safeContext.classes[0].id);
                }
            }

            if (isNaN(resolvedClassId) || !resolvedClassId) {
                throw new Error("Không xác định được ID lớp học để thêm học sinh. Vui lòng chọn lớp học hoặc cung cấp classId hợp lệ.");
            }

            const params = { ...(studentData || {}), classId: resolvedClassId };
            const res = await WHITELISTED_SERVER_ACTIONS['add_student'](actorUser, orgId, params);
            executedBatch.push({ action: 'add_student', params, result: res });
            return res;
        }));

        await jail.set('_updateStudent', wrapSafeApi(async (studentIdOrObj, studentObj) => {
            let targetStudentId = studentIdOrObj;
            let studentData = studentObj;

            if (typeof studentIdOrObj === 'object' && studentIdOrObj !== null) {
                studentData = studentIdOrObj;
                targetStudentId = studentData.id || studentData.studentId;
            }
            if (typeof targetStudentId === 'string' && isNaN(Number(targetStudentId))) {
                const found = (safeContext.currentStudents || []).find(s => s.name && s.name.toLowerCase() === targetStudentId.trim().toLowerCase());
                if (found) targetStudentId = found.id;
            }
            const resolvedStudentId = Number(targetStudentId);
            if (isNaN(resolvedStudentId) || !resolvedStudentId) {
                throw new Error("Không xác định được ID học sinh để cập nhật.");
            }
            const params = { ...(studentData || {}), studentId: resolvedStudentId };
            const res = await WHITELISTED_SERVER_ACTIONS['update_student'](actorUser, orgId, params);
            executedBatch.push({ action: 'update_student', params, result: res });
            return res;
        }));

        await jail.set('_deleteStudent', wrapSafeApi(async (studentIdOrObj) => {
            let targetStudentId = studentIdOrObj;
            if (typeof studentIdOrObj === 'object' && studentIdOrObj !== null) {
                targetStudentId = studentIdOrObj.id || studentIdOrObj.studentId;
            }
            if (typeof targetStudentId === 'string' && isNaN(Number(targetStudentId))) {
                const found = (safeContext.currentStudents || []).find(s => s.name && s.name.toLowerCase() === targetStudentId.trim().toLowerCase());
                if (found) targetStudentId = found.id;
            }
            const resolvedStudentId = Number(targetStudentId);
            if (isNaN(resolvedStudentId) || !resolvedStudentId) {
                throw new Error("Không xác định được ID học sinh để xóa.");
            }
            const params = { studentId: resolvedStudentId };
            const res = await WHITELISTED_SERVER_ACTIONS['delete_student'](actorUser, orgId, params);
            executedBatch.push({ action: 'delete_student', params, result: res });
            return res;
        }));

        await jail.set('_deductConductScore', wrapSafeApi(async (studentIdOrObj, points, reason) => {
            let targetStudentId = studentIdOrObj;
            let pts = points;
            let rsn = reason;

            if (typeof studentIdOrObj === 'object' && studentIdOrObj !== null) {
                targetStudentId = studentIdOrObj.studentId || studentIdOrObj.id;
                pts = points !== undefined ? points : studentIdOrObj.points;
                rsn = reason || studentIdOrObj.reason;
            }
            if (typeof targetStudentId === 'string' && isNaN(Number(targetStudentId))) {
                const found = (safeContext.currentStudents || []).find(s => s.name && s.name.toLowerCase() === targetStudentId.trim().toLowerCase());
                if (found) targetStudentId = found.id;
            }
            const resolvedStudentId = Number(targetStudentId);
            if (isNaN(resolvedStudentId) || !resolvedStudentId) {
                throw new Error("Không xác định được ID học sinh để trừ điểm hạnh kiểm.");
            }
            const params = { studentId: resolvedStudentId, points: Number(pts) || 0, reason: String(rsn || '') };
            const res = await WHITELISTED_SERVER_ACTIONS['deduct_conduct_score'](actorUser, orgId, params);
            executedBatch.push({ action: 'deduct_conduct_score', params, result: res });
            return res;
        }));

        // Log capture function that collects logs into executionLogs array and outputs to host console
        await jail.set('_log', new ivm.Reference((msg) => {
            const str = typeof msg === 'string' ? msg : JSON.stringify(msg);
            executionLogs.push(str);
            console.log('[isolated-vm AI Execution Log]:', str);
        }));

        // Script bootstrap inside isolated V8 context
        const bootstrapScript = `
            const callHost = async (fnRef, ...args) => {
                const res = await fnRef.apply(undefined, args, { arguments: { copy: true }, result: { promise: true, copy: true } });
                if (res && !res.ok) {
                    throw new Error(res.error || 'Lỗi không xác định khi thực thi trên Server');
                }
                return res ? res.data : undefined;
            };
            const callHostSync = (fnRef, ...args) => fnRef.applySync(undefined, args, { arguments: { copy: true } });

            const createClass = (...args) => callHost(_createClass, ...args);
            const deleteClass = (...args) => callHost(_deleteClass, ...args);
            const getClasses = (...args) => callHost(_getClasses, ...args);
            const getStudents = (...args) => callHost(_getStudents, ...args);
            const getAcademicYears = (...args) => callHost(_getAcademicYears, ...args);
            const createAcademicYear = (...args) => callHost(_createAcademicYear, ...args);
            const deleteAcademicYear = (...args) => callHost(_deleteAcademicYear, ...args);
            const inviteMember = (...args) => callHost(_inviteMember, ...args);
            const addStudent = (...args) => callHost(_addStudent, ...args);
            const updateStudent = (...args) => callHost(_updateStudent, ...args);
            const deleteStudent = (...args) => callHost(_deleteStudent, ...args);
            const deductConductScore = (...args) => callHost(_deductConductScore, ...args);
            const console = {
                log: (...args) => {
                    const str = args.map(a => {
                        try {
                            return typeof a === 'object' ? JSON.stringify(a) : String(a);
                        } catch(e) {
                            return String(a);
                        }
                    }).join(' ');
                    callHostSync(_log, str);
                }
            };

            (async function __runUserCode() {
                ${cleanScript}
            })().then(val => {
                if (val !== undefined) {
                    try {
                        return typeof val === 'object' ? JSON.stringify(val) : String(val);
                    } catch(e) {
                        return String(val);
                    }
                }
                return undefined;
            });
        `;

        try {
            const script = await isolate.compileScript(bootstrapScript);
            const promiseRef = await script.run(v8Context, { timeout: 10000, promise: true });
            let rawVal = promiseRef;
            if (promiseRef && typeof promiseRef.then === 'function') {
                rawVal = await promiseRef;
            }
            if (typeof rawVal === 'string') {
                try {
                    executionResult = JSON.parse(rawVal);
                } catch (e) {
                    executionResult = rawVal;
                }
            } else {
                executionResult = rawVal;
            }
        } catch (err) {
            console.error('[isolated-vm Sandbox Execution Error]:', err);
            throw new Error(`Lỗi khi thực thi mã JavaScript trên Server (isolated-vm): ${err.message}`);
        } finally {
            isolate.dispose();
        }
    } else if (Array.isArray(planActions)) {
        // Fallback execution for planActions array
        for (const item of planActions) {
            const handler = WHITELISTED_SERVER_ACTIONS[item.action];
            if (!handler) {
                console.warn(`[Server AI Bridge Security Alert] Blocked non-whitelisted action: ${item.action}`);
                continue;
            }

            try {
                const result = await handler(actorUser, orgId, item.params);
                executedBatch.push({
                    action: item.action,
                    params: item.params,
                    result
                });
            } catch (err) {
                console.error(`[Server AI Bridge Error] Failed to execute ${item.action}:`, err);
                throw err;
            }
        }
    }

    if (executedBatch.length > 0) {
        history.push(executedBatch);
        redoStack.length = 0; // Reset redo stack
    }

    // Call Agent Post-Execution Reflection so Agent receives execution results and reasons/thinks
    let feedback = null;
    if (userPrompt || codeScript) {
        feedback = await generateAgentExecutionFeedback(
            userPrompt || 'Thực thi kịch bản',
            codeScript,
            { success: true, logs: executionLogs, result: executionResult, executedBatch },
            safeContext
        );
    }

    return {
        success: true,
        executedCount: executedBatch.length,
        canUndo: history.length > 0,
        canRedo: redoStack.length > 0,
        logs: executionLogs,
        result: executionResult,
        executedBatch,
        agentThought: feedback?.thought || null,
        agentReply: feedback?.reply || null
    };
}

/**
 * Autonomous Multi-turn Agent Execution Loop (ReAct: Think -> Execute -> Observe -> Think)
 * Runs up to maxTurns iterations allowing the Agent to reason, run commands, receive outputs, and continue reasoning.
 */
export async function runAgentLoopOnServer(actorUser, orgId, prompt, screenContext = {}, fileData = null, maxTurns = 3) {
    let currentContext = { ...(screenContext || {}) };
    const turns = [];
    let lastFeedback = null;
    let finalThought = '';
    let finalReply = '';
    const allExecutedBatches = [];

    for (let i = 0; i < maxTurns; i++) {
        // Step 1: Agent reasons and outputs thought + code (incorporating previous execution feedback if any)
        const geminiRes = await callGeminiApi(prompt, currentContext, (i === 0 ? fileData : null), lastFeedback);
        if (!geminiRes) {
            break;
        }

        finalThought = geminiRes.thought || '';
        finalReply = geminiRes.reply || '';
        const code = geminiRes.code ? geminiRes.code.trim() : '';

        // If no code to execute, Agent has concluded its thinking and response
        if (!code) {
            turns.push({
                turn: i + 1,
                thought: finalThought,
                code: null,
                logs: [],
                result: null,
                executedBatch: []
            });
            break;
        }

        // Step 2: Execute command/code on server in isolated-vm
        let execResult;
        try {
            execResult = await executeAiPlanOnServer(actorUser, orgId, null, code, currentContext, null);
        } catch (err) {
            execResult = {
                success: false,
                logs: [],
                result: null,
                executedBatch: [],
                error: err.message
            };
        }

        turns.push({
            turn: i + 1,
            thought: finalThought,
            code,
            logs: execResult.logs || [],
            result: execResult.result,
            executedBatch: execResult.executedBatch || [],
            success: execResult.success !== false,
            error: execResult.error || null
        });

        if (execResult.executedBatch && execResult.executedBatch.length) {
            allExecutedBatches.push(...execResult.executedBatch);
        }

        // Feed execution result back to the Agent for the next turn
        lastFeedback = {
            success: execResult.success !== false,
            logs: execResult.logs || [],
            result: execResult.result,
            executedBatch: execResult.executedBatch || [],
            error: execResult.error || null
        };
    }

    // Synthesize final thought & reply from the Agent based on the completed execution
    if (lastFeedback) {
        const finalReview = await generateAgentExecutionFeedback(prompt, '', lastFeedback, currentContext);
        if (finalReview) {
            finalThought = finalReview.thought || finalThought;
            finalReply = finalReview.reply || finalReply;
        }
    }

    return {
        success: true,
        prompt,
        thought: finalThought,
        reply: finalReply,
        turns,
        allExecutedBatches
    };
}

/**
 * 3. Revert/Undo last action batch directly on Server
 */
export async function undoAiActionOnServer(orgId) {
    const history = getOrgHistory(orgId);
    const redoStack = getOrgRedo(orgId);

    if (history.length === 0) {
        throw new Error('Không có thao tác nào trên Server để hoàn tác');
    }

    const lastBatch = history.pop();
    const revertedBatch = [];

    for (let i = lastBatch.length - 1; i >= 0; i--) {
        const item = lastBatch[i];
        const reverser = SERVER_REVERSAL_HANDLERS[item.action];
        if (reverser) {
            try {
                await reverser(orgId, item.params, item.result);
                revertedBatch.push(item);
            } catch (err) {
                console.error(`[Server AI Bridge Undo Error] Reverting ${item.action} failed:`, err);
            }
        }
    }

    redoStack.push(lastBatch);

    return {
        success: true,
        revertedCount: revertedBatch.length,
        canUndo: history.length > 0,
        canRedo: redoStack.length > 0
    };
}

/**
 * 4. Redo last undone action batch directly on Server
 */
export async function redoAiActionOnServer(orgId) {
    const history = getOrgHistory(orgId);
    const redoStack = getOrgRedo(orgId);

    if (redoStack.length === 0) {
        throw new Error('Không có thao tác nào trên Server để làm lại');
    }

    const batchToRedo = redoStack.pop();
    const reexecutedBatch = [];

    for (const item of batchToRedo) {
        const handler = WHITELISTED_SERVER_ACTIONS[item.action];
        if (handler) {
            const result = await handler(orgId, item.params);
            reexecutedBatch.push({
                action: item.action,
                params: item.params,
                result
            });
        }
    }

    history.push(reexecutedBatch);

    return {
        success: true,
        reexecutedCount: reexecutedBatch.length,
        canUndo: history.length > 0,
        canRedo: redoStack.length > 0
    };
}

/**
 * Get current Undo/Redo state for an Organization
 */
export function getAiBridgeState(orgId) {
    const history = getOrgHistory(orgId);
    const redoStack = getOrgRedo(orgId);
    return {
        canUndo: history.length > 0,
        canRedo: redoStack.length > 0
    };
}
