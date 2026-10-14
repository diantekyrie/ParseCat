import { useEffect, useState } from "react";
import App from "./App.jsx";
import { setToken, setUnauthorizedHandler } from "./authSession.js";
import "./LoginGate.css";

// Wraps the real App behind a login form backed by POST /api/auth/login
// (see backend/app/auth.py). Deliberately plain component state for
// `authed`, not persisted anywhere -- a refresh remounts this component
// from scratch, which is what forces the login screen again on refresh.
// A session timing out server-side arrives the same way a page refresh
// does: the next API call 401s, authSession's unauthorizedHandler fires,
// and this flips back to the login form.
export default function LoginGate() {
  const [authed, setAuthed] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [expiredNotice, setExpiredNotice] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setAuthed(false);
      setExpiredNotice(true);
    });
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
