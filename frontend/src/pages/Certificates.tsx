import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime, upload } from "../api";
import { ErrorNote, PageHeader } from "../components/ui";

interface ActiveCert { mode: string; subject?: string; not_after?: string; days_left?: number; sans?: string[]; covers_fqdn?: boolean; error?: string }
interface CertRow { id: number; status: string; source: string; fingerprint: string; subject: string; issuer: string; serial: string; sans: string[]; key_type: string; not_before: string; not_after: string; warnings: string[]; created_by: string | null; activated_at: string | null }
interface Csr { id: number; status: string; common_name: string; sans: string[]; key_type: string; created_by: string | null; created_at: string; csr_pem?: string }
interface Status {
  features: { ui_tls_management: boolean; acme: boolean }; deployment: string; fqdn: string | null; public_url: string; tls_mode: string; hsts: boolean;
  urls: Record<string, string>; active: ActiveCert | null; proxy_available: boolean; history: CertRow[]; pending_csrs: Csr[]; trusted_ca: string[];
  acme: { enabled: boolean; email?: string; challenge?: string; dns_provider?: string | null; directory_url?: string | null };
}
interface Report { ok: boolean; errors: string[]; warnings: string[]; info: Record<string, unknown> }

function Card({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2"><h2 className="font-heading font-bold">{title}</h2>{actions}</div>
      {children}
    </section>
  );
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return <div className="flex gap-3 border-t border-ec-surface-alt py-1.5 text-sm first:border-t-0"><dt className="w-36 shrink-0 text-ec-slate">{k}</dt><dd className="break-all">{v ?? "—"}</dd></div>;
}

function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return <button type="button" className="text-xs underline" onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); }); }}>{done ? "Copied" : "Copy"}</button>;
}

function ReportView({ r }: { r: Report }) {
  return (
    <div role="status" className={`rounded-sm px-3 py-2 text-sm ${r.ok ? "bg-emerald-50 text-emerald-900" : "bg-red-50 text-red-800"}`}>
      <strong>{r.ok ? "Validation passed" : "Validation failed"}</strong>
      {r.errors.length > 0 && <ul className="ml-5 list-disc">{r.errors.map((e) => <li key={e}>{e}</li>)}</ul>}
      {r.warnings.length > 0 && <ul className="ml-5 list-disc text-amber-900">{r.warnings.map((w) => <li key={w}>{w}</li>)}</ul>}
      {r.ok && Array.isArray(r.info.chain) && <p className="mt-1 text-xs">Chain: {(r.info.chain as string[]).join(" → ")}</p>}
    </div>
  );
}

function InstallForm({ onDone }: { onDone: () => void }) {
  const [mode, setMode] = useState<"pem" | "pfx" | "paste">("pem");
  const [report, setReport] = useState<Report | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const run = async (form: HTMLFormElement, path: "validate" | "install") => {
    setBusy(true); setErr(null);
    try {
      const fd = new FormData(form);
      for (const [k, v] of [...fd.entries()]) if (v instanceof File && v.size === 0) fd.delete(k);
      if (path === "validate") setReport(await upload<Report>("/api/settings/certificates/validate", fd));
      else { await upload("/api/settings/certificates/install", fd); setReport(null); form.reset(); onDone(); }
    } catch (e) { setErr(e); } finally { setBusy(false); }
  };
  return (
    <form className="space-y-3" onSubmit={(e: FormEvent<HTMLFormElement>) => { e.preventDefault(); run(e.currentTarget, "install"); }}>
      <div role="tablist" className="flex gap-2 text-sm">
        {(["pem", "pfx", "paste"] as const).map((m) => (
          <button key={m} type="button" role="tab" aria-selected={mode === m} className={mode === m ? "btn-primary" : "btn-secondary"} onClick={() => { setMode(m); setReport(null); }}>
            {m === "pem" ? "PEM files" : m === "pfx" ? "PKCS#12 / PFX" : "Paste PEM"}
          </button>
        ))}
      </div>
      {mode === "pem" && (
        <div className="grid gap-3 md:grid-cols-3">
          <div><label className="label" htmlFor="c-cert">Certificate (or full bundle)</label><input id="c-cert" name="cert" type="file" accept=".pem,.crt,.cer" className="text-sm" required /></div>
          <div><label className="label" htmlFor="c-key">Private key</label><input id="c-key" name="key" type="file" accept=".pem,.key" className="text-sm" /></div>
          <div><label className="label" htmlFor="c-chain">Intermediate chain</label><input id="c-chain" name="chain" type="file" accept=".pem,.crt" className="text-sm" /></div>
        </div>
      )}
      {mode === "pfx" && <div><label className="label" htmlFor="c-pfx">PKCS#12 / PFX file</label><input id="c-pfx" name="pfx" type="file" accept=".pfx,.p12" className="text-sm" required /></div>}
      {mode === "paste" && <div><label className="label" htmlFor="c-paste">Certificate, private key and chain (PEM)</label><textarea id="c-paste" name="pasted" rows={8} className="input w-full font-mono text-xs" required spellCheck={false} /></div>}
      {mode !== "paste" && <div><label className="label" htmlFor="c-pw">{mode === "pfx" ? "PFX password" : "Key password (if encrypted)"}</label><input id="c-pw" name="password" type="password" className="input w-64" autoComplete="off" /></div>}
      {report && <ReportView r={report} />}
      <ErrorNote error={err} />
      <div className="flex gap-2">
        <button type="button" className="btn-secondary" disabled={busy} onClick={(e) => run(e.currentTarget.form!, "validate")}>Validate</button>
        <button className="btn-primary" disabled={busy}>{busy ? "Working…" : "Validate & activate"}</button>
      </div>
      <p className="text-xs text-ec-slate">The private key is encrypted at rest and is never shown or exported again. Activation hot-reloads the proxy and checks that the new certificate is served; on failure the previous one is restored automatically.</p>
    </form>
  );
}

function CsrForm({ fqdn, onDone }: { fqdn: string | null; onDone: (c: Csr) => void }) {
  const m = useMutation({ mutationFn: (body: Record<string, unknown>) => api<Csr>("/api/settings/certificates/csr", { method: "POST", body }), onSuccess: onDone });
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const g = (k: string) => (String(fd.get(k) ?? "").trim() || null);
    m.mutate({ common_name: g("cn"), sans: String(fd.get("sans") ?? "").split(/[\s,]+/).filter(Boolean), key_type: g("key_type"),
               organization: g("o"), org_unit: g("ou"), locality: g("l"), state: g("st"), country: g("c"), email: g("email") });
  };
  return (
    <form onSubmit={submit} className="grid gap-3 md:grid-cols-3">
      <div><label className="label" htmlFor="cn">Common name</label><input id="cn" name="cn" className="input w-full" defaultValue={fqdn ?? ""} required /></div>
      <div className="md:col-span-2"><label className="label" htmlFor="sans">Additional SANs</label><input id="sans" name="sans" className="input w-full" placeholder="www.example.com, 10.0.0.5" /></div>
      <div><label className="label" htmlFor="key_type">Key type</label>
        <select id="key_type" name="key_type" className="input w-full" defaultValue="ecdsa-p256">
          <option value="ecdsa-p256">ECDSA P-256</option><option value="ecdsa-p384">ECDSA P-384</option>
          <option value="rsa-2048">RSA 2048</option><option value="rsa-3072">RSA 3072</option><option value="rsa-4096">RSA 4096</option>
        </select></div>
      <div><label className="label" htmlFor="o">Organization</label><input id="o" name="o" className="input w-full" /></div>
      <div><label className="label" htmlFor="ou">Organizational unit</label><input id="ou" name="ou" className="input w-full" /></div>
      <div><label className="label" htmlFor="l">City</label><input id="l" name="l" className="input w-full" /></div>
      <div><label className="label" htmlFor="st">State / province</label><input id="st" name="st" className="input w-full" /></div>
      <div><label className="label" htmlFor="c">Country (2 letters)</label><input id="c" name="c" className="input w-full" maxLength={2} /></div>
      <div className="md:col-span-3"><ErrorNote error={m.error} /><button className="btn-primary" disabled={m.isPending}>{m.isPending ? "Generating…" : "Generate CSR"}</button>
        <span className="ml-2 text-xs text-ec-slate">The private key is generated and stays on the server.</span></div>
    </form>
  );
}

function PendingCsr({ c, onChange }: { c: Csr; onChange: () => void }) {
  const [err, setErr] = useState<unknown>(null);
  const cancel = useMutation({ mutationFn: () => api(`/api/settings/certificates/csr/${c.id}`, { method: "DELETE" }), onSuccess: onChange });
  const complete = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault(); setErr(null);
    try { await upload(`/api/settings/certificates/csr/${c.id}/complete`, new FormData(e.currentTarget)); onChange(); } catch (x) { setErr(x); }
  };
  return (
    <li className="rounded-sm border border-ec-border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2"><strong>{c.common_name}</strong><span className="text-ec-slate">{c.key_type} · {fmtDateTime(c.created_at)}</span>
        <a className="link ml-auto" href={`/api/settings/certificates/csr/${c.id}/download`}>Download CSR</a>
        <button className="text-xs text-red-800 underline" onClick={() => cancel.mutate()}>Cancel</button></div>
      <form onSubmit={complete} className="mt-2 flex flex-wrap items-end gap-2">
        <div><label className="label" htmlFor={`s-${c.id}`}>Signed certificate</label><input id={`s-${c.id}`} name="cert" type="file" className="text-sm" required /></div>
        <div><label className="label" htmlFor={`ch-${c.id}`}>Chain (optional)</label><input id={`ch-${c.id}`} name="chain" type="file" className="text-sm" /></div>
        <button className="btn-primary">Upload & activate</button>
      </form>
      <ErrorNote error={err ?? cancel.error} />
    </li>
  );
}

export default function CertificatesSettings() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["certificates"], queryFn: () => api<Status>("/api/settings/certificates") });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["certificates"] }); qc.invalidateQueries({ queryKey: ["system-banners"] }); };
  const rollback = useMutation({ mutationFn: () => api("/api/settings/certificates/rollback", { method: "POST" }), onSuccess: refresh });
  const [newCsr, setNewCsr] = useState<Csr | null>(null);
  const [caErr, setCaErr] = useState<unknown>(null);
  const removeCa = useMutation({ mutationFn: () => api("/api/settings/certificates/trusted-ca", { method: "DELETE" }), onSuccess: refresh });
  const acme = useMutation({ mutationFn: (body: Record<string, unknown>) => api("/api/settings/certificates/acme", { method: "PUT", body }), onSuccess: refresh });
  const d = q.data;
  if (q.error) return <ErrorNote error={q.error} />;
  if (!d) return null;
  const managed = d.features.ui_tls_management;
  const a = d.active;
  const prev = d.history.find((h) => h.status === "previous");

  return (
    <>
      <PageHeader title="Certificates & Domain" helpId="settings-certificates" subtitle="TLS certificate for the built-in proxy, domain and derived URLs" />
      <div className="space-y-4">
        {!managed && <p className="rounded-sm border border-ec-border bg-ec-surface-alt px-3 py-2 text-sm">Certificate management is turned off (<code>features.ui_tls_management</code>). This page shows the current state; enable the flag in <code>config/exposurecatalyst.yaml</code> and run <code>./run.sh</code> to install certificates, generate CSRs or roll back.</p>}

        <Card title="Current certificate" actions={managed && prev ? <button className="btn-secondary" disabled={rollback.isPending} onClick={() => window.confirm(`Roll back to the previous certificate (${prev.subject})?`) && rollback.mutate()}>Roll back to previous</button> : undefined}>
          <ErrorNote error={rollback.error} />
          {a ? (
            <dl>
              <Row k="Source" v={a.mode === "self-signed" ? <span className="rounded-sm bg-amber-50 px-1.5 text-amber-900">Self-signed (generated)</span> : a.mode} />
              <Row k="Subject" v={a.subject} />
              <Row k="SANs" v={a.sans?.join(", ")} />
              <Row k="Expires" v={a.not_after ? `${fmtDateTime(a.not_after)} (${a.days_left} days)` : null} />
              <Row k="Matches domain" v={d.fqdn ? (a.covers_fqdn ? "Yes" : <span className="text-red-800">No — the certificate does not cover {d.fqdn}</span>) : "No FQDN configured"} />
              {d.history.filter((h) => h.status === "active").map((h) => (
                <div key={h.id} className="contents">
                  <Row k="Issuer" v={h.issuer} /><Row k="Serial" v={h.serial} /><Row k="Key" v={h.key_type} />
                  <Row k="SHA-256" v={<code className="text-xs">{h.fingerprint}</code>} />
                  {h.warnings.length > 0 && <Row k="Warnings" v={h.warnings.join("; ")} />}
                </div>))}
            </dl>
          ) : <p className="text-sm text-ec-slate">No proxy certificate on this deployment (the built-in proxy is used by the Docker deployment).</p>}
          <p className="mt-2 text-xs text-ec-slate">TLS 1.2+ only (1.3 preferred) · HTTP redirects to HTTPS · HSTS {d.hsts ? "on" : "off"} · proxy {d.proxy_available ? "reachable" : "not reachable"}</p>
        </Card>

        <Card title="Domain">
          <dl>
            <Row k="FQDN" v={d.fqdn ?? <span className="text-ec-slate">not set (using EXCAT_PUBLIC_URL)</span>} />
            {Object.entries(d.urls).map(([k, v]) => <Row key={k} k={k} v={<span className="flex gap-2"><code className="text-xs">{v}</code><Copy text={v} /></span>} />)}
          </dl>
          <p className="mt-2 text-xs text-ec-slate">To change the domain: set <code>fqdn</code> in <code>config/exposurecatalyst.yaml</code> and run <code>./run.sh</code>. Then update DNS, Okta (download the new SP metadata) and the certificate.</p>
        </Card>

        {managed && (<>
          <Card title="Install a certificate"><InstallForm onDone={refresh} /></Card>
          <Card title="Generate a CSR">
            <CsrForm fqdn={d.fqdn} onDone={(c) => { setNewCsr(c); refresh(); }} />
            {newCsr?.csr_pem && <div className="mt-3"><p className="text-sm">Send this CSR to your CA, then upload the signed certificate below.</p><pre className="mt-1 max-h-40 overflow-auto rounded bg-ec-surface-alt p-2 text-xs">{newCsr.csr_pem}</pre><Copy text={newCsr.csr_pem} /></div>}
            {d.pending_csrs.length > 0 && <ul className="mt-3 space-y-2">{d.pending_csrs.map((c) => <PendingCsr key={c.id} c={c} onChange={refresh} />)}</ul>}
          </Card>
          <Card title="Trusted CA bundle (outbound)" actions={d.trusted_ca.length > 0 ? <button className="text-xs text-red-800 underline" onClick={() => removeCa.mutate()}>Remove</button> : undefined}>
            <p className="mb-2 text-sm text-ec-slate">Internal root/issuing CAs and TLS-inspection proxies trusted for outbound connections (CVE sources, integrations, AI providers, SMTP), in addition to the public roots. Also used to validate uploaded certificates.</p>
            {d.trusted_ca.length > 0 && <ul className="mb-2 ml-5 list-disc text-sm">{d.trusted_ca.map((s) => <li key={s}><code className="text-xs">{s}</code></li>)}</ul>}
            <form className="flex flex-wrap items-end gap-2" onSubmit={async (e) => { e.preventDefault(); setCaErr(null); try { await upload("/api/settings/certificates/trusted-ca", new FormData(e.currentTarget), "PUT"); refresh(); } catch (x) { setCaErr(x); } }}>
              <div><label className="label" htmlFor="ca">PEM bundle</label><input id="ca" name="bundle" type="file" accept=".pem,.crt" className="text-sm" required /></div>
              <button className="btn-secondary">Upload</button>
            </form>
            <ErrorNote error={caErr ?? removeCa.error} />
          </Card>
          {d.features.acme && (
            <Card title="ACME / Let's Encrypt">
              <p className="mb-2 text-sm text-ec-slate">The proxy obtains and renews the certificate itself. Requires a public FQDN that resolves to this host and, for HTTP-01, port 80 reachable from the internet. DNS-01 credentials come from the environment (<code>EXCAT_ACME_CLOUDFLARE_API_TOKEN</code> or AWS credentials for Route 53).</p>
              <form className="grid gap-3 md:grid-cols-4" onSubmit={(e) => { e.preventDefault(); const fd = new FormData(e.currentTarget); acme.mutate({ enabled: fd.get("enabled") === "on", email: fd.get("email") || null, challenge: fd.get("challenge"), dns_provider: fd.get("dns_provider") || null, directory_url: fd.get("directory_url") || null }); }}>
                <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="enabled" defaultChecked={d.acme.enabled} /> Use ACME</label>
                <div><label className="label" htmlFor="ae">Contact email</label><input id="ae" name="email" type="email" className="input w-full" defaultValue={d.acme.email ?? ""} /></div>
                <div><label className="label" htmlFor="ach">Challenge</label><select id="ach" name="challenge" className="input w-full" defaultValue={d.acme.challenge ?? "http-01"}><option value="http-01">HTTP-01</option><option value="dns-01">DNS-01</option></select></div>
                <div><label className="label" htmlFor="adp">DNS provider</label><select id="adp" name="dns_provider" className="input w-full" defaultValue={d.acme.dns_provider ?? ""}><option value="">—</option><option value="route53">Route 53</option><option value="cloudflare">Cloudflare</option></select></div>
                <div className="md:col-span-3"><label className="label" htmlFor="adir">Directory URL (optional: staging / internal ACME CA)</label><input id="adir" name="directory_url" className="input w-full" defaultValue={d.acme.directory_url ?? ""} placeholder="https://acme-staging-v02.api.letsencrypt.org/directory" /></div>
                <div className="flex items-end"><button className="btn-primary" disabled={acme.isPending}>Save</button></div>
              </form>
              <ErrorNote error={acme.error} />
            </Card>
          )}
        </>)}

        {d.history.length > 0 && (
          <Card title="History">
            <div className="overflow-x-auto"><table className="min-w-full text-sm">
              <thead className="bg-ec-surface-alt"><tr><th className="th">Status</th><th className="th">Subject</th><th className="th">Expires</th><th className="th">Source</th><th className="th">Activated</th></tr></thead>
              <tbody>{d.history.map((h) => <tr key={h.id} className="border-t border-ec-surface-alt"><td className="td capitalize">{h.status}</td><td className="td break-all">{h.subject}</td><td className="td">{fmtDateTime(h.not_after)}</td><td className="td">{h.source}</td><td className="td">{fmtDateTime(h.activated_at)}{h.created_by && ` · ${h.created_by}`}</td></tr>)}</tbody>
            </table></div>
          </Card>
        )}
      </div>
    </>
  );
}
