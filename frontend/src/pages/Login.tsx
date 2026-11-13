import { useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Me } from "../api";
import { InfoTip } from "../help";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const nav = useNavigate();
  const [params] = useSearchParams();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const me = await api<Me>("/api/auth/login", { method: "POST", body: { username, password, totp_code: needCode ? code : undefined } });
      qc.setQueryData(["me"], me);
      const next = params.get("next") ?? "/cves";
      nav(next.startsWith("/") && !next.startsWith("//") ? next : "/cves", { replace: true }); // no open redirect
    } catch (err) {
      if (err instanceof ApiError && (err.detail as { mfa_required?: boolean })?.mfa_required) {
        setNeedCode(true);
        setError(null);
      } else {
        setError(err instanceof Error ? err.message : "Sign-in failed");
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-brand-900 px-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl bg-white p-6 shadow-xl" aria-labelledby="login-title">
        <h1 id="login-title" className="text-xl font-bold text-slate-900">ExposureCatalyst</h1>
        <p className="mb-5 text-sm text-slate-600">Vulnerability Intelligence &amp; Advisory Platform</p>
        <button type="button" disabled className="btn-secondary mb-4 w-full justify-center" title="Okta SAML sign-in arrives in Phase 4">
          Sign in with Okta (coming soon)
        </button>
        <div className="mb-4 flex items-center gap-2 text-xs text-slate-400"><span className="h-px flex-1 bg-slate-200" />local account<InfoTip k="local_account" /><span className="h-px flex-1 bg-slate-200" /></div>
        <label className="label" htmlFor="u">Username</label>
        <input id="u" className="input mb-3 w-full" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <label className="label" htmlFor="p">Password</label>
        <input id="p" type="password" className="input mb-3 w-full" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        {needCode && (
          <>
            <label className="label" htmlFor="c">Verification code<InfoTip k="mfa" /></label>
            <input id="c" className="input mb-3 w-full tracking-widest" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6}
                   value={code} onChange={(e) => setCode(e.target.value)} required autoFocus />
          </>
        )}
        {error && <p role="alert" className="mb-3 rounded bg-red-50 px-3 py-2 text-sm text-red-800">{error}</p>}
        <button className="btn-primary w-full justify-center" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div>
  );
}
