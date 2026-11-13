import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime } from "../api";
import { ErrorNote, PageHeader } from "../components/ui";

interface SamlCfg {
  enabled: boolean; idp_entity_id: string; idp_sso_url: string; idp_x509_cert: string; sp_entity_id: string;
  attr_email: string; attr_first_name: string; attr_last_name: string; attr_groups: string;
  allow_idp_initiated: boolean; jit_provisioning: boolean; mappings: number; app_tile: string;
  sp: { entity_id: string; acs: string; metadata: string; login: string };
}
interface Mappings {
  mappings: { id: number; group_name: string; role_id: number; role: string; users: number }[];
  unmapped_groups: string[]; sso_users: number; users_without_access: number; scim_groups: number; last_scim_activity: string | null;
}
interface Role { id: number; name: string }
interface Token { id: number; name: string; created_at: string; last_used_at: string | null; revoked: boolean }

function Step({ n, title, done, children }: { n: number; title: string; done?: boolean; children: ReactNode }) {
  return (
    <section className="card">
      <h2 className="mb-3 flex items-center gap-2 font-heading font-bold">
        <span className={`inline-flex h-7 w-7 items-center justify-center rounded-full text-sm ${done ? "bg-emerald-600 text-white" : "bg-ec-navy text-white"}`} aria-hidden="true">{done ? "✓" : n}</span>
        Step {n} — {title}{done && <span className="sr-only"> (complete)</span>}
      </h2>
      {children}
    </section>
  );
}

function Copy({ label, value }: { label: string; value: string }) {
  const [ok, setOk] = useState(false);
  return (
    <div className="mb-2">
      <div className="label">{label}</div>
      <div className="flex gap-2">
        <code className="flex-1 break-all rounded-sm bg-ec-surface-alt px-2 py-1.5 text-xs">{value}</code>
        <button type="button" className="btn-secondary" onClick={async () => { await navigator.clipboard.writeText(value); setOk(true); setTimeout(() => setOk(false), 1500); }}>{ok ? "Copied" : "Copy"}</button>
      </div>
    </div>
  );
}

export default function SsoSettings() {
  const qc = useQueryClient();
  const cfg = useQuery({ queryKey: ["saml"], queryFn: () => api<SamlCfg>("/api/settings/sso/saml") });
  const maps = useQuery({ queryKey: ["sso-maps"], queryFn: () => api<Mappings>("/api/settings/sso/mappings") });
  const roles = useQuery({ queryKey: ["rbac"], queryFn: () => api<{ roles: Role[] }>("/api/admin/rbac") });
  const tokens = useQuery({ queryKey: ["scim-tokens"], queryFn: () => api<Token[]>("/api/settings/scim/tokens") });
  const [newToken, setNewToken] = useState<{ token: string; base_url: string } | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const refresh = () => { qc.invalidateQueries({ queryKey: ["saml"] }); qc.invalidateQueries({ queryKey: ["sso-maps"] }); };

  const importMd = useMutation({ mutationFn: (body: Record<string, string>) => api<SamlCfg>("/api/settings/sso/saml/metadata", { method: "POST", body }),
                                 onSuccess: () => { refresh(); setMsg("IdP metadata imported."); } });
  const save = useMutation({ mutationFn: (body: Partial<SamlCfg>) => api<SamlCfg>("/api/settings/sso/saml", { method: "PUT", body }),
                             onSuccess: () => { refresh(); setMsg("Saved."); } });
  const addMap = useMutation({ mutationFn: (body: { group_name: string; role_id: number }) => api("/api/settings/sso/mappings", { method: "POST", body }), onSuccess: refresh });
  const delMap = useMutation({ mutationFn: (id: number) => api(`/api/settings/sso/mappings/${id}`, { method: "DELETE" }), onSuccess: refresh });
  const mkToken = useMutation({ mutationFn: (name: string) => api<{ token: string; base_url: string }>("/api/settings/scim/tokens", { method: "POST", body: { name } }),
                                onSuccess: (t) => { setNewToken(t); qc.invalidateQueries({ queryKey: ["scim-tokens"] }); } });
  const revoke = useMutation({ mutationFn: (id: number) => api(`/api/settings/scim/tokens/${id}`, { method: "DELETE" }),
                               onSuccess: () => qc.invalidateQueries({ queryKey: ["scim-tokens"] }) });

  const c = cfg.data;
  if (!c) return null;
  const imported = Boolean(c.idp_entity_id && c.idp_sso_url && c.idp_x509_cert);
  const full = (patch: Partial<SamlCfg>) => {
    const { idp_entity_id, idp_sso_url, idp_x509_cert, sp_entity_id, attr_email, attr_first_name, attr_last_name, attr_groups, allow_idp_initiated, jit_provisioning, enabled } = c;
    return { idp_entity_id, idp_sso_url, idp_x509_cert, sp_entity_id, attr_email, attr_first_name, attr_last_name, attr_groups, allow_idp_initiated, jit_provisioning, enabled, ...patch };
  };

  return (
    <>
      <PageHeader title="Identity & SSO" helpId="settings-sso" subtitle="Okta SAML 2.0 sign-in · SailPoint group → role mapping · SCIM 2.0 provisioning" />
      {msg && <p role="status" className="mb-3 rounded-sm bg-ec-surface-alt px-3 py-2 text-sm">{msg}</p>}
      <ErrorNote error={importMd.error ?? save.error ?? addMap.error ?? delMap.error ?? mkToken.error} />
      <div className="space-y-4">
        <Step n={1} title="Create the ExposureCatalyst app in Okta" done={imported}>
          <p className="mb-3 text-sm text-ec-slate">Okta Admin → Applications → Create App Integration → <strong>SAML 2.0</strong>. Use these values:</p>
          <Copy label="Single sign-on URL (ACS) — also 'Recipient' and 'Destination'" value={c.sp.acs} />
          <Copy label="Audience URI (SP Entity ID)" value={c.sp.entity_id} />
          <div className="mt-3 grid gap-3 text-sm md:grid-cols-2">
            <div>
              <div className="label">Settings</div>
              <ul className="ml-4 list-disc text-ec-slate"><li>Name ID format: EmailAddress · Application username: Email</li><li>Response: Signed (default) · Assertion signature: Signed · SHA-256</li>
                <li>Attribute statements: <code>email</code>, <code>firstName</code>, <code>lastName</code></li><li>Group attribute statement: <code>groups</code> — filter e.g. <em>Starts with</em> <code>Excat</code></li></ul>
            </div>
            <div>
              <div className="label">Downloads</div>
              <p className="mb-2"><a className="link" href="/api/saml/metadata">SP metadata XML</a> — some Okta orgs can import it directly.</p>
              <p className="flex items-center gap-2"><img src="/brand/png/app-icon-64.png" alt="" aria-hidden="true" className="h-8 w-8 rounded" />
                <a className="link" href={c.app_tile} download="exposurecatalyst-app-icon-512.png">App tile logo (512×512 PNG)</a> — Okta → General → App logo.</p>
            </div>
          </div>
        </Step>

        <Step n={2} title="Import the Okta IdP metadata" done={imported}>
          <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); importMd.mutate({ url: String(new FormData(e.currentTarget).get("url")) }); }}>
            <div className="flex-1"><label className="label" htmlFor="mdurl">Metadata URL (Okta → Sign On tab → "Metadata URL")</label>
              <input id="mdurl" name="url" type="url" className="input w-full" placeholder="https://acme.okta.com/app/exk…/sso/saml/metadata" required /></div>
            <button className="btn-primary" disabled={importMd.isPending}>Import from URL</button>
          </form>
          <details className="mt-2"><summary className="cursor-pointer text-sm">…or paste the metadata XML</summary>
            <form className="mt-2 space-y-2" onSubmit={(e) => { e.preventDefault(); importMd.mutate({ xml: String(new FormData(e.currentTarget).get("xml")) }); }}>
              <textarea name="xml" rows={6} className="input w-full font-mono text-xs" required aria-label="IdP metadata XML" />
              <button className="btn-secondary">Import XML</button>
            </form>
          </details>
          {imported && <dl className="mt-3 grid gap-1 text-xs md:grid-cols-2"><div><dt className="label">IdP entity ID</dt><dd className="break-all">{c.idp_entity_id}</dd></div>
            <div><dt className="label">IdP SSO URL</dt><dd className="break-all">{c.idp_sso_url}</dd></div></dl>}
        </Step>

        <Step n={3} title="Attributes and provisioning" done={imported}>
          <form className="grid gap-3 md:grid-cols-4" onSubmit={(e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const fd = new FormData(e.currentTarget);
            save.mutate(full({ attr_email: String(fd.get("attr_email")), attr_first_name: String(fd.get("attr_first_name")), attr_last_name: String(fd.get("attr_last_name")),
                               attr_groups: String(fd.get("attr_groups")), jit_provisioning: fd.get("jit") === "on", allow_idp_initiated: fd.get("idpi") === "on" })); }}>
            {(["attr_email", "attr_first_name", "attr_last_name", "attr_groups"] as const).map((k) => (
              <div key={k}><label className="label" htmlFor={k}>{k.replace("attr_", "").replace("_", " ")} attribute</label><input id={k} name={k} className="input w-full" defaultValue={c[k]} /></div>))}
            <label className="flex items-center gap-2 text-sm md:col-span-2"><input type="checkbox" name="jit" defaultChecked={c.jit_provisioning} />Create users on first sign-in (JIT). Turn off if SailPoint provisions via SCIM.</label>
            <label className="flex items-center gap-2 text-sm md:col-span-2"><input type="checkbox" name="idpi" defaultChecked={c.allow_idp_initiated} />Allow IdP-initiated sign-in (Okta dashboard tile). Off is safer.</label>
            <div><button className="btn-primary" disabled={!imported}>Save attributes</button></div>
          </form>
        </Step>

        <Step n={4} title="Map SailPoint / Okta groups to roles" done={(maps.data?.mappings.length ?? 0) > 0}>
          <p className="mb-2 text-sm text-ec-slate">SSO users get roles <strong>only</strong> through these mappings (from the SAML <code>groups</code> attribute or SCIM group membership). Users whose groups map to nothing cannot sign in.</p>
          <table className="mb-3 min-w-full text-sm">
            <thead className="bg-ec-surface-alt"><tr><th className="th">Group</th><th className="th">Role</th><th className="th">Users</th><th className="th" /></tr></thead>
            <tbody>{maps.data?.mappings.map((m) => (
              <tr key={m.id} className="border-t border-ec-surface-alt"><td className="td font-mono text-xs">{m.group_name}</td><td className="td">{m.role}</td><td className="td">{m.users}</td>
                <td className="td"><button className="text-xs text-red-800 underline" onClick={() => delMap.mutate(m.id)}>Remove</button></td></tr>))}
            </tbody>
          </table>
          <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); const fd = new FormData(e.currentTarget);
            addMap.mutate({ group_name: String(fd.get("g")), role_id: Number(fd.get("r")) }, { onSuccess: () => (e.target as HTMLFormElement).reset() }); }}>
            <div><label className="label" htmlFor="g">Group name (exact)</label><input id="g" name="g" className="input w-64" list="unmapped" required /></div>
            <datalist id="unmapped">{maps.data?.unmapped_groups.map((g) => <option key={g} value={g} />)}</datalist>
            <div><label className="label" htmlFor="r">Role</label><select id="r" name="r" className="input">{roles.data?.roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></div>
            <button className="btn-primary">Add mapping</button>
          </form>
          {maps.data && <p className="mt-3 text-xs text-ec-slate">Sync status: {maps.data.sso_users} SSO user(s) · {maps.data.users_without_access} without access · {maps.data.scim_groups} SCIM group(s) · last SCIM activity {fmtDateTime(maps.data.last_scim_activity)}
            {maps.data.unmapped_groups.length > 0 && <> · unmapped groups seen: <code>{maps.data.unmapped_groups.slice(0, 8).join(", ")}</code></>}</p>}
        </Step>

        <Step n={5} title="Enable and test" done={c.enabled}>
          <div className="flex flex-wrap items-center gap-3">
            <button className="btn-primary" disabled={!imported || save.isPending} onClick={() => save.mutate(full({ enabled: !c.enabled }))}>{c.enabled ? "Disable SAML sign-in" : "Enable SAML sign-in"}</button>
            {c.enabled && <a className="btn-secondary" href={`${c.sp.login}?next=/cves`} target="_blank" rel="noopener noreferrer">Test sign-in in a new tab ↗</a>}
            <span className="text-xs text-ec-slate">Keep this session open while testing. Local break-glass accounts keep working if SSO fails.</span>
          </div>
        </Step>

        <section className="card">
          <h2 className="mb-2 font-heading font-bold">SailPoint SCIM 2.0 provisioning</h2>
          <p className="mb-3 text-sm text-ec-slate">Configure a SCIM 2.0 source/connector in SailPoint IdentityNow (ISC) or IdentityIQ with base URL <code>{c.sp.entity_id.replace("/api/saml/metadata", "/scim/v2")}</code> and a bearer token below. Group membership drives roles through the mappings above.</p>
          {newToken && <div role="alert" className="mb-3 rounded-sm border border-amber-400 bg-amber-50 p-3 text-sm"><strong>Copy this token now — it will not be shown again.</strong><Copy label="SCIM base URL" value={newToken.base_url} /><Copy label="Bearer token" value={newToken.token} /></div>}
          <form className="mb-3 flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); mkToken.mutate(String(new FormData(e.currentTarget).get("tn"))); }}>
            <div><label className="label" htmlFor="tn">Token name</label><input id="tn" name="tn" className="input" defaultValue="SailPoint ISC" required minLength={2} /></div>
            <button className="btn-primary">Generate token</button>
          </form>
          <table className="min-w-full text-sm"><thead className="bg-ec-surface-alt"><tr><th className="th">Name</th><th className="th">Created</th><th className="th">Last used</th><th className="th" /></tr></thead>
            <tbody>{tokens.data?.map((t) => (<tr key={t.id} className="border-t border-ec-surface-alt"><td className="td">{t.name}{t.revoked && <span className="ml-1 text-xs text-ec-slate">(revoked)</span>}</td>
              <td className="td text-xs">{fmtDateTime(t.created_at)}</td><td className="td text-xs">{fmtDateTime(t.last_used_at)}</td>
              <td className="td">{!t.revoked && <button className="text-xs text-red-800 underline" onClick={() => revoke.mutate(t.id)}>Revoke</button>}</td></tr>))}</tbody></table>
        </section>
      </div>
    </>
  );
}
