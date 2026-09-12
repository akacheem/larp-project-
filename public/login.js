import { login } from "./clientAuth.js";

async function submitLogin() {
    const statusText = document.getElementById("status-text");
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const res = await login(email, password);
    if (res.ok) {
        statusText.className = "text-xs font-semibold text-emerald-400";
        statusText.innerText = "Đăng nhập thành công!";
        setTimeout(() => {
            window.location.href = "/dashboard";
        }, 500);
    } else {
        statusText.className = "text-xs font-semibold text-red-400";
        statusText.innerText = res.message || "Đăng nhập thất bại!";
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("submit-btn").addEventListener("click", (e) => {
        submitLogin();
        e.preventDefault();
    });
})

