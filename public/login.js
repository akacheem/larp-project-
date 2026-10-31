import { login } from "./clientAuth.js";

async function submitLogin() {
    const statusText = document.getElementById("status-text");
    const submitBtn = document.getElementById("submit-btn");
    const email = document.getElementById("email") ? document.getElementById("email").value.trim() : "";
    const password = document.getElementById("password") ? document.getElementById("password").value : "";

    if (!email || !password) {
        if (statusText) {
            statusText.className = "text-xs font-semibold text-amber-500";
            statusText.innerText = "Vui lòng nhập đầy đủ Email và Mật khẩu!";
        }
        return;
    }

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.classList.add("opacity-75", "cursor-not-allowed");
    }

    if (statusText) {
        statusText.className = "text-xs font-medium text-blue-500";
        statusText.innerText = "Đang xác thực thông tin...";
    }

    try {
        const res = await login(email, password);
        if (res.ok) {
            if (statusText) {
                statusText.className = "text-xs font-semibold text-emerald-600";
                statusText.innerText = "Đăng nhập thành công! Đang chuyển hướng...";
            }
            setTimeout(() => {
                window.location.href = "/dashboard";
            }, 500);
        } else {
            if (statusText) {
                statusText.className = "text-xs font-semibold text-rose-500";
                statusText.innerText = res.message || "Email hoặc mật khẩu không chính xác!";
            }
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.classList.remove("opacity-75", "cursor-not-allowed");
            }
        }
    } catch (err) {
        if (statusText) {
            statusText.className = "text-xs font-semibold text-rose-500";
            statusText.innerText = "Lỗi kết nối máy chủ!";
        }
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.classList.remove("opacity-75", "cursor-not-allowed");
        }
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const submitBtn = document.getElementById("submit-btn");
    const form = document.querySelector("form");

    if (form) {
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            submitLogin();
        });
    }

    if (submitBtn) {
        submitBtn.addEventListener("click", (e) => {
            e.preventDefault();
            submitLogin();
        });
    }
});
