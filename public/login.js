import { login } from "./clientAuth.js";

async function submitLogin() {
    const statusText = document.getElementById("status-text");
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    if ((await login(email, password)).ok) {
        statusText.innerText = "Đăng nhập thành công!"
        setTimeout(() => {
            window.location.href = "/";
        }, 500);
    } else {
        statusText.innerText = "Đăng nhập thất bại!"
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("submit-btn").addEventListener("click", (e) => {
        submitLogin();
        e.preventDefault();
    });
})

