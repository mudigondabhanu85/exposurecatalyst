import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

/** First-run wizard (empty installation only): setup token → administrator account → authenticator (MFA). */
export default function SetupPage() {
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [token, setToken] = useState("");
  const [account, setAccount] = useState({ username: "", email: "", password: "", confirm: "" });
  const [mfa, setMfa] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const auth = { Authorization: `Bearer ${token.trim()}` };

  const run = async (fn: () => Promise<void>) => {
    setBusy(true); setError(null);
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : "Something went wrong"); } finally { setBusy(false); }
  };
  const verify = (e: FormEvent) => { e.preventDefault(); run(async () => { await api("/api/setup/verify", { headers: auth }); setStep(2); }); };
  const begin = (e: FormEvent) => {
    e.preventDefault();
    if (account.password !== account.confirm) { setError("Passwords do not match"); return; }
    run(async () => {
      setMfa(await api<{ secret: string; otpauth_uri: string }>("/api/setup/begin", { method: "POST", headers: auth,
        body: { username: account.username, email: account.email || null, password: account.password } }));
      setStep(3);
    });
  };
  const complete = (e: FormEvent) => { e.preventDefault(); run(async () => { await api("/api/setup/complete", { method: "POST", headers: auth, body: { totp_code: code } }); setStep(4); }); };

  return (
    <div className="flex min-h-screen items-center justify-center bg-ec-surface px-4 py-8">
      <div className="w-full max-w-md rounded-md border border-ec-border bg-white p-6 shadow-sm">
        <img src="/brand/svg/logo-light.svg" alt="ExposureCatalyst" className="mx-auto mb-4 w-56 max-w-full" />
        <h1 className="font-heading text-lg font-bold">First-run setup</h1>
        <ol className="mb-4 mt-1 flex gap-2 text-xs text-ec-slate" aria-label="Progress">
          {["Setup token", "Administrator", "Authenticator", "Done"].map((s, i) => (
            <li key={s} aria-current={step === i + 1 ? "step" : undefined} className={step === i + 1 ? "font-semibold text-ec-navy" : ""}>{i + 1}. {s}</li>
          ))}
        </ol>
        {error && <p role="alert" className="mb-3 rounded bg-red-50 px-3 py-2 text-sm text-red-800">{error}</p>}

        {step === 1 && (
          <form onSubmit={verify} className="space-y-3">
            <p className="text-sm text-ec-slate">A one-time setup token was printed to the API logs when the application started:</p>
            <pre className="overflow-x-auto rounded bg-ec-surface-alt px-2 py-1 text-xs">docker compose logs api | grep -A3 "setup token"</pre>
            <label className="label" htmlFor="tok">Setup token</label>
            <input id="tok" className="input w-full font-mono" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" required minLength={8} />
            <button className="btn-primary w-full justify-center" disabled={busy}>Continue</button>
          </form>
        )}

        {step === 2 && (
          <form onSubmit={begin} className="space-y-3">
            <p className="text-sm text-ec-slate">Create the break-glass <strong>Super Admin</strong>. Keep it for emergencies once SSO is configured.</p>
            <div><label className="label" htmlFor="u">Username</label><input id="u" className="input w-full" value={account.username} onChange={(e) => setAccount({ ...account, username: e.target.value })} required minLength={3} autoComplete="username" /></div>
            <div><label className="label" htmlFor="em">Email (optional)</label><input id="em" type="email" className="input w-full" value={account.email} onChange={(e) => setAccount({ ...account, email: e.target.value })} /></div>
            <div><label className="label" htmlFor="pw">Password</label><input id="pw" type="password" className="input w-full" value={account.password} onChange={(e) => setAccount({ ...account, password: e.target.value })} required autoComplete="new-password" /></div>
            <div><label className="label" htmlFor="pw2">Repeat password</label><input id="pw2" type="password" className="input w-full" value={account.confirm} onChange={(e) => setAccount({ ...account, confirm: e.target.value })} required autoComplete="new-password" /></div>
            <button className="btn-primary w-full justify-center" disabled={busy}>Continue</button>
          </form>
        )}

        {step === 3 && mfa && (
          <form onSubmit={complete} className="space-y-3">
            <p className="text-sm text-ec-slate">Multi-factor authentication is required. Add this account to your authenticator app, then enter the 6-digit code.</p>
            <div className="rounded bg-ec-surface-alt p-2 text-xs">
              <div>Secret: <code className="break-all font-mono">{mfa.secret}</code></div>
              <a className="link break-all" href={mfa.otpauth_uri}>Open in authenticator app</a>
            </div>
            <label className="label" htmlFor="code">Authenticator code</label>
            <input id="code" className="input w-full font-mono tracking-widest" inputMode="numeric" pattern="\d{6}" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="one-time-code" />
            <button className="btn-primary w-full justify-center" disabled={busy}>Create administrator</button>
          </form>
        )}

        {step === 4 && (
          <div className="space-y-3">
            <p role="status" className="rounded bg-emerald-50 px-3 py-2 text-sm text-emerald-900">Administrator <strong>{account.username}</strong> created. The setup token has been invalidated.</p>
            <Link to="/login" className="btn-primary w-full justify-center">Sign in</Link>
          </div>
        )}
      </div>
    </div>
  );
}
