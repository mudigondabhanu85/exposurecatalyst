import { useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";

/** First sign-in of the default break-glass account: replace the generated password, then enrol MFA. */
export default function FirstLoginPage() {
  const { me, refresh } = useAuth();
  const [mfa, setMfa] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const step = me?.must_change_password ? 1 : 2;

  const run = async (fn: () => Promise<void>) => {
    setBusy(true); setError(null);
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : "Something went wrong"); } finally { setBusy(false); }
  };
  const changePassword = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    if (fd.get("new") !== fd.get("again")) { setError("New passwords do not match"); return; }
    run(async () => { await api("/api/auth/password", { method: "POST", body: { current_password: fd.get("current"), new_password: fd.get("new") } }); refresh(); });
  };
  const startMfa = () => run(async () => setMfa(await api<{ secret: string; otpauth_uri: string }>("/api/auth/mfa/setup", { method: "POST" })));
  const enableMfa = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const code = String(new FormData(e.currentTarget).get("code"));
    run(async () => { await api("/api/auth/mfa/enable", { method: "POST", body: { totp_code: code } }); refresh(); });
  };
  const logout = async () => { await api("/api/auth/logout", { method: "POST" }).catch(() => undefined); window.location.assign("/login"); };

  return (
    <div className="flex min-h-screen items-center justify-center bg-ec-surface px-4 py-8">
      <div className="w-full max-w-md rounded-md border border-ec-border bg-white p-6 shadow-sm">
        <img src="/brand/svg/logo-light.svg" alt="ExposureCatalyst" className="mx-auto mb-4 w-56 max-w-full" />
        <h1 className="font-heading text-lg font-bold">Secure the break-glass account</h1>
        <p className="mb-3 text-sm text-ec-slate">Signed in as <strong>{me?.username}</strong>. Step {step} of 2: {step === 1 ? "replace the generated password" : "enrol an authenticator app (required for administrators)"}.</p>
        {error && <p role="alert" className="mb-3 rounded bg-red-50 px-3 py-2 text-sm text-red-800">{error}</p>}
        {step === 1 && (
          <form onSubmit={changePassword} className="space-y-3">
            <div><label className="label" htmlFor="fl-cur">Generated password</label><input id="fl-cur" name="current" type="password" className="input w-full" required autoComplete="current-password" /></div>
            <div><label className="label" htmlFor="fl-new">New password</label><input id="fl-new" name="new" type="password" className="input w-full" required autoComplete="new-password" /></div>
            <div><label className="label" htmlFor="fl-again">Repeat new password</label><input id="fl-again" name="again" type="password" className="input w-full" required autoComplete="new-password" /></div>
            <button className="btn-primary w-full justify-center" disabled={busy}>Change password</button>
          </form>
        )}
        {step === 2 && !mfa && <button className="btn-primary w-full justify-center" disabled={busy} onClick={startMfa}>Set up authenticator</button>}
        {step === 2 && mfa && (
          <form onSubmit={enableMfa} className="space-y-3">
            <div className="rounded bg-ec-surface-alt p-2 text-xs"><div>Secret: <code className="break-all font-mono">{mfa.secret}</code></div>
              <a className="link break-all" href={mfa.otpauth_uri}>Open in authenticator app</a></div>
            <label className="label" htmlFor="fl-code">Authenticator code</label>
            <input id="fl-code" name="code" className="input w-full font-mono tracking-widest" inputMode="numeric" pattern="\d{6}" maxLength={6} required autoComplete="one-time-code" />
            <button className="btn-primary w-full justify-center" disabled={busy}>Verify and continue</button>
          </form>
        )}
        <p className="mt-4 text-xs text-ec-slate">Next: create named accounts (Settings → Users &amp; RBAC) or configure SSO, and keep this account for emergencies. <button className="underline" onClick={logout}>Sign out</button></p>
      </div>
    </div>
  );
}
