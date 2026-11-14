// Access token for ParseCat's per-user login -- see backend/app/auth.py.
// Deliberately held ONLY in this module-level variable, never
// localStorage/sessionStorage, so it never outlives this tab's JS
// execution on its own. What makes a page refresh painless now (instead of
// forcing a real login every time, the original design here) is a SEPARATE
// long-lived refresh token behind an httpOnly cookie, invisible to this
// file by design (JS can't read an httpOnly cookie even if it wanted to) --
// LoginGate.jsx exchanges it for a fresh access token on load via
// refreshAccessToken() below. A real login screen only shows up once that
// refresh token itself is gone (expired, or revoked by logoutSession()).

let token = null;
let unauthorizedHandler = null;

export function setToken(t) {
  token = t;
}

export function clearToken() {
  token = null;
}

export function hasToken() {
  return Boolean(token);
}

export function getAuthHeader() {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// LoginGate registers itself here on mount so a 401 from any API call that
// the refresh-and-retry in App.jsx's api() couldn't recover from -- the
// refresh token itself is dead, not just the access token -- can flip the
// app back to the login screen from wherever that happened, without
// threading a callback prop through every call site. `reason` lets
// LoginGate show different copy for "your session ended" (expiry) vs a
// deliberate "Sign out" click.
export function setUnauthorizedHandler(fn) {
  unauthorizedHandler = fn;
}

export function notifyUnauthorized() {
  clearToken();
  if (unauthorizedHandler) unauthorizedHandler("expired");
}

// Exchanges the httpOnly refresh cookie for a new access token. Used both
// on page load (LoginGate, to skip the login form entirely when possible)
// and reactively from App.jsx's api() helper on an unexpected 401, so an
// access token expiring mid-session is invisible rather than bouncing the
// user to a login screen. credentials: "same-origin" is the fetch default
// for a same-origin request already, but set explicitly since this is the
// one place in the app that actually depends on a cookie being sent.
export async function refreshAccessToken() {
  try {
    const res = await fetch("/api/auth/refresh", { method: "POST", credentials: "same-origin" });
    if (!res.ok) {
      clearToken();
      return false;
    }
    const data = await res.json();
    setToken(data.token);
    return true;
  } catch {
    clearToken();
    return false;
  }
}

// A deliberate "Sign out," not just letting the access token lapse: revokes
// the refresh token server-side (see backend's POST /api/auth/logout) so a
// copy of the cookie made before logout stops working too, then clears
// local state and flips the app back to the login screen with neutral
// copy (not "your session ended," which would be misleading here).
export async function logoutSession() {
  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  } catch {
    // Best-effort -- local state still clears below even if the request
    // itself failed (e.g. offline), so the UI never gets stuck "logged in."
  }
  clearToken();
  if (unauthorizedHandler) unauthorizedHandler("logged_out");
}
