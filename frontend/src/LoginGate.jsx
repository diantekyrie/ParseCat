import { useEffect, useState } from "react";
import App from "./App.jsx";
import { setToken, setUnauthorizedHandler } from "./authSession.js";

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
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh" }}>
        <form onSubmit={handleSubmit} style={{ width: "280px", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          <h1 style={{ margin: 0 }}>ParseCat</h1>
          <p style={{ margin: 0, color: "#888" }}>Sign in to continue.</p>
          {expiredNotice && (
            <p style={{ margin: 0, color: "#b35900" }}>Your session ended. Please sign in again.</p>
          )}
          <label style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
            Username
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              autoComplete="username"
            />
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          {error && <div style={{ color: "#c0392b" }}>{error}</div>}
          <button type="submit" disabled={busy || !username || !password}>
            {busy ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </div>
    );
  }

  return <App />;
}
