import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Me } from "../api";
import { InfoTip } from "../help";

/** Internal paths only: "/x" — never "//host", "/\\host" (browsers treat "\\" as "/") or a scheme. */
export function safeNext(next: string | null): string {
  if (!next || !/^\/(?![/\\])/.test(next) || next.includes("\\") || /[\u0000-\u001f]/.test(next)) return "/cves";
  return next;
}

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
  const sso = useQuery({ queryKey: ["sso-status"], queryFn: () => api<{ saml_enabled: boolean; login_url: string }>("/api/auth/sso") });
  const ssoError = params.get("sso_error");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const me = await api<Me>("/api/auth/login", { method: "POST", body: { username, password, totp_code: needCode ? code : undefined } });
      qc.setQueryData(["me"], me);
      const next = params.get("next") ?? "/cves";
      nav(safeNext(next), { replace: true });
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
    <div className="flex min-h-screen items-center justify-center bg-ec-surface px-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-md border border-ec-border bg-white p-6 shadow-sm" aria-labelledby="login-title">
        {/* Full lockup incl. tagline; ≥160 px wide per brand minimum. The h1 is for screen readers. */}
        <img src="/brand/svg/logo-light.svg" alt="ExposureCatalyst" className="mx-auto mb-6 w-64 max-w-full" />
        <h1 id="login-title" className="sr-only">Sign in to ExposureCatalyst</h1>
        {ssoError && <p role="alert" className="mb-3 rounded bg-red-50 px-3 py-2 text-sm text-red-800">Single sign-on failed: {ssoError}</p>}
        {sso.data?.saml_enabled ? (
          <a className="btn-primary mb-4 w-full justify-center" href={`${sso.data.login_url}?next=${encodeURIComponent(params.get("next") ?? "/cves")}`}>Sign in with Okta</a>
        ) : (
          <button type="button" disabled className="btn-secondary mb-4 w-full justify-center" title="An administrator has not enabled Okta sign-in yet">Sign in with Okta (not configured)</button>
        )}
        <div className="mb-4 flex items-center gap-2 text-xs text-ec-slate"><span className="h-px flex-1 bg-ec-border" />local account<InfoTip k="local_account" /><span className="h-px flex-1 bg-ec-border" /></div>
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
