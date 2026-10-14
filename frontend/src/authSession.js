// Session token for ParseCat's shared-credential login -- see
// backend/app/auth.py. Deliberately held ONLY in this module-level variable,
// never localStorage/sessionStorage/a cookie, so a page refresh always wipes
// it and re-shows the login screen (LoginGate.jsx), same as closing and
// reopening the tab. The token also carries its own server-checked expiry
// (PARSECAT_SESSION_TIMEOUT_SECONDS, default 900s), so a tab left open and
// idle loses access automatically even without a refresh.

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

// LoginGate registers itself here on mount so a 401 from any API call
// (expired/invalid token) can flip the app back to the login screen from
// wherever App.jsx's api() helper happens to be, without threading a
// callback prop through every call site.
export function setUnauthorizedHandler(fn) {
  unauthorizedHandler = fn;
}

export function notifyUnauthorized() {
  clearToken();
  if (unauthorizedHandler) unauthorizedHandler();
}
