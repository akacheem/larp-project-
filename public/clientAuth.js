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

export function decodeAuthToken() {
    if (!isAlreadyLogin())
        throw new Error("ERROR_AUTH_TOKEN_EMPTY");

    try {
        const token = localStorage.getItem("authToken");
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => 
            '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
        ).join(''));
        return JSON.parse(jsonPayload);
    } catch {
        throw new Error("ERROR_BAD_JWT_TOKEN");
    }
}

export function getAuthToken() {
    if (!isAlreadyLogin())
        throw new Error("ERROR_AUTH_TOKEN_EMPTY");

    return localStorage.getItem("authToken");
}

export function logout() {
    localStorage.removeItem("authToken");
}

export function clientLogout() {
    logout();
}

export async function login(email, password) {
    const resp = await fetch("/submit-login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: email, password: password }) });
    const resj = await resp.json();

    if (!resp.ok)
        return { ok: false, message: resj.message };

    setAuthToken(resj.token);
    return { ok: true, message: "ok" };
}