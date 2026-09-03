import jsonwebtoken from "https://cdn.jsdelivr.net/npm/jsonwebtoken@9.0.3/+esm";

function setAuthToken(tok) {
    localStorage.setItem("authToken", tok);
}

export async function signup(username, email, password, isOrganizationAccount) {
    var res = await fetch("/submit-signup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: username, email: email, isOrganization: isOrganizationAccount, password: password }) });
    var jres = await res.json();

    if (!res.ok) {
        throw new Error(jres.message);
    }

    if (!jres.token) {
        throw new Error("BAD_SERVER_RESPONSE");
    }

    setAuthToken(jres.token);
}

export function isAlreadyLogin() {
    return localStorage.getItem("authToken") !== null;
}

export async function decodeAuthToken() {
    if (!isAlreadyLogin())
        throw new Error("ERROR_AUTH_TOKEN_EMPTY")

    try {
        const decodedDat = await jsonwebtoken.decode(localStorage.getItem("authToken"));
        return decodedDat
    } catch {
        throw new Error("ERROR_BAD_JWT_TOKEN");
    }
}

export function getAuthToken() {
    if (!isAlreadyLogin())
        throw new Error("ERROR_AUTH_TOKEN_EMPTY")

    return localStorage.getItem("authToken")
}

export function logout() {
    localStorage.removeItem("authToken");
}

export async function login(email, password) {
    const resp = await fetch("/submit-login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: email, password: password }) });
    console.log(resp);
    const resj = await resp.json();

    if (!resp.ok)
        return { ok: false, message: resj.message };

    setAuthToken(resj.token);
    return { ok: true, message: "ok" };
}