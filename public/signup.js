import { signup } from "./clientAuth.js";

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("signup-form");
    const submitBtn = document.getElementById("submit-btn");

    if (form) {
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            submitSignup();
        });
    }

    if (submitBtn) {
        submitBtn.addEventListener("click", (e) => {
            e.preventDefault();
            submitSignup();
        });
    }
});

export async function submitSignup() {
    const submitBtn = document.getElementById("submit-btn");
    const btnText = document.getElementById("btn-text");
    const usernameInput = document.getElementById("username");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const confirmPasswordInput = document.getElementById("confirm-password");
    const isOrganizationInput = document.getElementById("isOrganization");

    const username = (usernameInput?.value || "").trim();
    const email = (emailInput?.value || "").trim();
    const password = passwordInput?.value || "";
    const confirmPassword = confirmPasswordInput?.value || "";
    const isOrganizationAccount = Boolean(isOrganizationInput?.checked);

    if (!username) {
        showStatus("Vui lòng nhập Họ và Tên hoặc Tên tổ chức!", false);
        usernameInput?.focus();
        return;
    }

    if (!email) {
        showStatus("Vui lòng nhập địa chỉ Email!", false);
        emailInput?.focus();
        return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showStatus("Địa chỉ Email không đúng định dạng (vd: name@example.com)!", false);
        emailInput?.focus();
        return;
    }

    if (!password) {
        showStatus("Vui lòng nhập mật khẩu!", false);
        passwordInput?.focus();
        return;
    }

    if (password.length < 8) {
        showStatus("Mật khẩu phải có tối thiểu 8 ký tự!", false);
        passwordInput?.focus();
        return;
    }

    if (password !== confirmPassword) {
        showStatus("Mật khẩu xác nhận không trùng khớp!", false);
        confirmPasswordInput?.focus();
        return;
    }

    // Set Loading State
    if (submitBtn) submitBtn.disabled = true;
    if (btnText) btnText.innerText = "Đang tạo tài khoản...";
    showStatus("Đang kiểm tra và tạo tài khoản...", null);

    try {
        const res = await signup(username, email, password, isOrganizationAccount);
        if (res.ok) {
            showStatus("Đăng ký thành công! Đang chuyển hướng...", true);
            setTimeout(() => {
                window.location.href = "/dashboard";
            }, 600);
        } else {
            showStatus(res.message || "Đăng ký không thành công, vui lòng thử lại!", false);
            if (submitBtn) submitBtn.disabled = false;
            if (btnText) btnText.innerText = "Tạo tài khoản";
        }
    } catch (e) {
        console.error(e);
        showStatus(e.message || "Lỗi kết nối máy chủ!", false);
        if (submitBtn) submitBtn.disabled = false;
        if (btnText) btnText.innerText = "Tạo tài khoản";
    }
}

function showStatus(msg, isSuccess) {
    const statusText = document.getElementById("status-text");
    if (!statusText) return;

    if (isSuccess === true) {
        statusText.className = "text-xs font-semibold text-[#34c759] flex items-center justify-center gap-1";
        statusText.innerText = msg;
    } else if (isSuccess === false) {
        statusText.className = "text-xs font-semibold text-[#ff3b30] flex items-center justify-center gap-1";
        statusText.innerText = msg;
    } else {
        statusText.className = "text-xs font-semibold text-[#0071e3] flex items-center justify-center gap-1";
        statusText.innerText = msg;
    }
}
