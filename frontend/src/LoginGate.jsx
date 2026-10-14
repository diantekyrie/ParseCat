import { useEffect, useState } from "react";
import App from "./App.jsx";
import { refreshAccessToken, setToken, setUnauthorizedHandler } from "./authSession.js";
import "./LoginGate.css";

// Wraps the real App behind a login form backed by POST /api/auth/login
// (see backend/app/auth.py). `authed` is plain component state, not
// persisted anywhere, so a page refresh remounts this component from
// scratch -- but unlike the original single-token design, that no longer
// means a forced re-login: the mount effect below tries refreshAccessToken()
// first (the httpOnly refresh cookie survives a refresh even though this
// component's own state doesn't), and only falls through to the login form
// if that fails. `authed` is a tri-state (null while that check is in
// flight) specifically to avoid flashing the login form for a moment
// before the silent check resolves.
export default function LoginGate() {
  const [authed, setAuthed] = useState(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [expiredNotice, setExpiredNotice] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler((reason) => {
      setAuthed(false);
      setExpiredNotice(reason === "expired");
    });
    refreshAccessToken().then(setAuthed);
    return () => setUnauthorizedHandler(null);
  }, []);

  async function handleSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
        credentials: "same-origin", // so the Set-Cookie refresh token response actually gets stored
      });
      if (!res.ok) {
        let detail = `Login failed (${res.status}).`;
        try {
          const body = await res.json();
          if (typeof body?.detail === "string") detail = body.detail;
        } catch {
          // non-JSON error body -- keep the generic message above
        }
        setError(detail);
        return;
      }
      const data = await res.json();
      setToken(data.token);
      setExpiredNotice(false);
      setPassword("");
      setAuthed(true);
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  if (authed === null) {
    // Silent refresh-cookie check still in flight -- render nothing rather
    // than flashing the login form for a moment before (likely) hiding it
    // again once the refresh succeeds.
    return null;
  }

  if (!authed) {
    return (
      <div className="login-screen">
        <form className="login-card" onSubmit={handleSubmit}>
          <div className="login-brand">
            <span className="login-brand-mark">PC</span>
            <h1>ParseCat</h1>
          </div>
          <p className="login-subtitle">Sign in to diagnose device logs.</p>
          {expiredNotice && (
            <p className="login-notice">Your session ended. Please sign in again.</p>
          )}
          <label className="login-field">
            Username
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              autoComplete="username"
            />
          </label>
          <label className="login-field">
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          {error && <div className="login-error">{error}</div>}
          <button type="submit" className="login-submit" disabled={busy || !username || !password}>
            {busy ? "Signing in..." : "Sign in"}
          </button>
          <p className="login-footnote">Access is limited to people with a provisioned account.</p>
        </form>
      </div>
    );
  }

  return <App />;
}
