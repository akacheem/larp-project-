import { signup } from "./clientAuth.js";

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("submit-btn").addEventListener("click", (e) => {
        submitSignup();
        e.preventDefault();
    });
})

export async function submitSignup() {
    var username = document.getElementById("username").value;
    var email = document.getElementById("email").value;
    var password = document.getElementById("password").value;
    var isOrganizationAccount = document.getElementById("isOrganization").checked;

    try {
        await signup(username, email, password, isOrganizationAccount);
        setTimeout(() => {
            window.location.href = "/dashboard";
        }, 500);
    }
    catch (e) {
        console.log(e)
    }
}