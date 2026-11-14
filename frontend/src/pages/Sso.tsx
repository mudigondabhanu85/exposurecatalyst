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
interface OidcCfg {
  enabled: boolean; issuer: string; client_id: string; client_secret_set: boolean; token_auth_method: string; scopes: string;
  claim_email: string; claim_first_name: string; claim_last_name: string; claim_groups: string; jit_provisioning: boolean;
  button_label: string; redirect_uri: string; login_url: string;
}
interface OidcTest { ok: boolean; message: string; issuer?: string; token_endpoint?: string; userinfo_endpoint?: string | null; keys?: number }

/** OpenID Connect — the alternative to SAML. Same group → role mappings; secret is write-only. */
function OidcSection({ hasMappings }: { hasMappings: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["oidc"], queryFn: () => api<OidcCfg>("/api/settings/sso/oidc") });
  const [msg, setMsg] = useState<string | null>(null);
  const save = useMutation({ mutationFn: (body: Record<string, unknown>) => api<OidcCfg>("/api/settings/sso/oidc", { method: "PUT", body }),
                             onSuccess: (d) => { qc.setQueryData(["oidc"], d); setMsg("Saved."); } });
  const test = useMutation({ mutationFn: () => api<OidcTest>("/api/settings/sso/oidc/test", { method: "POST" }) });
  const c = q.data;
  if (!c) return null;
  const base = { issuer: c.issuer, client_id: c.client_id, client_secret: null, token_auth_method: c.token_auth_method, scopes: c.scopes,
                 claim_email: c.claim_email, claim_first_name: c.claim_first_name, claim_last_name: c.claim_last_name,
                 claim_groups: c.claim_groups, jit_provisioning: c.jit_provisioning, button_label: c.button_label, enabled: c.enabled };
  const ready = Boolean(c.issuer && c.client_id && c.client_secret_set);
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const secret = String(fd.get("o_secret") ?? "");
    const s = (k: string) => String(fd.get(k) ?? "");
    save.mutate({ ...base, issuer: s("o_issuer"), client_id: s("o_client"), client_secret: secret ? secret : null,
                  token_auth_method: s("o_method"), scopes: s("o_scopes"), claim_email: s("o_email"), claim_first_name: s("o_first"),
                  claim_last_name: s("o_last"), claim_groups: s("o_groups"), button_label: s("o_label"), jit_provisioning: fd.get("o_jit") === "on" },
                { onSuccess: () => (e.target as HTMLFormElement).reset() });
  };
  return (
    <section className="card" aria-labelledby="oidc-title" data-tour="oidc">
      <h2 id="oidc-title" className="mb-1 font-heading font-bold">Alternative: OpenID Connect (OIDC)</h2>
      <p className="mb-3 text-sm text-ec-slate">Use OIDC instead of — or alongside — SAML. Okta Admin → Applications → Create App Integration → <strong>OIDC – OpenID Connect</strong> → <strong>Web Application</strong>
        (grant type: Authorization Code). Add a <code>groups</code> claim to the ID token (Sign On → OpenID Connect ID Token → Groups claim filter, e.g. <em>Starts with</em> <code>Excat</code>). Roles come from the same group mappings above.</p>
      <Copy label="Sign-in redirect URI" value={c.redirect_uri} />
      {msg && <p role="status" className="my-2 rounded-sm bg-ec-surface-alt px-3 py-2 text-sm">{msg}</p>}
      <ErrorNote error={save.error ?? test.error} />
      <form className="mt-3 grid gap-3 md:grid-cols-2" onSubmit={submit}>
        <div><label className="label" htmlFor="o_issuer">Issuer URL</label>
          <input id="o_issuer" name="o_issuer" type="url" className="input w-full" defaultValue={c.issuer} placeholder="https://acme.okta.com/oauth2/default" /></div>
        <div><label className="label" htmlFor="o_client">Client ID</label><input id="o_client" name="o_client" className="input w-full" defaultValue={c.client_id} autoComplete="off" /></div>
        <div><label className="label" htmlFor="o_secret">Client secret {c.client_secret_set && <span className="text-ec-slate">(stored — leave blank to keep)</span>}</label>
          <input id="o_secret" name="o_secret" type="password" className="input w-full" autoComplete="new-password" placeholder={c.client_secret_set ? "••••••••" : ""} /></div>
        <div><label className="label" htmlFor="o_method">Client authentication</label>
          <select id="o_method" name="o_method" className="input w-full" defaultValue={c.token_auth_method}>
            <option value="client_secret_basic">Client secret (HTTP Basic) — Okta default</option><option value="client_secret_post">Client secret (POST body)</option></select></div>
        <div className="md:col-span-2"><label className="label" htmlFor="o_scopes">Scopes</label><input id="o_scopes" name="o_scopes" className="input w-full" defaultValue={c.scopes} /></div>
        <div><label className="label" htmlFor="o_email">Email claim</label><input id="o_email" name="o_email" className="input w-full" defaultValue={c.claim_email} /></div>
        <div><label className="label" htmlFor="o_groups">Groups claim</label><input id="o_groups" name="o_groups" className="input w-full" defaultValue={c.claim_groups} /></div>
        <div><label className="label" htmlFor="o_first">First-name claim</label><input id="o_first" name="o_first" className="input w-full" defaultValue={c.claim_first_name} /></div>
        <div><label className="label" htmlFor="o_last">Last-name claim</label><input id="o_last" name="o_last" className="input w-full" defaultValue={c.claim_last_name} /></div>
        <div><label className="label" htmlFor="o_label">Sign-in button label</label><input id="o_label" name="o_label" className="input w-full" defaultValue={c.button_label} maxLength={60} /></div>
        <label className="flex items-center gap-2 self-end text-sm"><input type="checkbox" name="o_jit" defaultChecked={c.jit_provisioning} />Create users on first sign-in (JIT)</label>
        <div className="flex flex-wrap gap-2 md:col-span-2">
          <button className="btn-primary" disabled={save.isPending}>Save OIDC settings</button>
          <button type="button" className="btn-secondary" disabled={!c.issuer || test.isPending} onClick={() => test.mutate()}>{test.isPending ? "Testing…" : "Test discovery"}</button>
        </div>
      </form>
      {test.data && <p role="status" className={`mt-3 rounded-sm px-3 py-2 text-sm ${test.data.ok ? "bg-emerald-50 text-emerald-900" : "bg-red-50 text-red-800"}`}>
        {test.data.message}{test.data.ok && <> · token endpoint <code>{test.data.token_endpoint}</code> · {test.data.keys} signing key(s)</>}</p>}
      <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-ec-surface-alt pt-3">
        <button className="btn-primary" disabled={!ready || !hasMappings || save.isPending} onClick={() => save.mutate({ ...base, enabled: !c.enabled })}>
          {c.enabled ? "Disable OIDC sign-in" : "Enable OIDC sign-in"}</button>
        {c.enabled && <a className="btn-secondary" href={`${c.login_url}?next=/cves`} target="_blank" rel="noopener noreferrer">Test sign-in in a new tab ↗</a>}
        {!hasMappings && <span className="text-xs text-ec-slate">Add a group mapping (Step 4) first.</span>}
        {!ready && <span className="text-xs text-ec-slate">Save the issuer, client ID and client secret first.</span>}
      </div>
    </section>
  );
}
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
      <PageHeader title="Identity & SSO" helpId="settings-sso" subtitle="Okta SAML 2.0 or OpenID Connect sign-in · SailPoint group → role mapping · SCIM 2.0 provisioning" />
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
          <p className="mb-2 text-sm text-ec-slate">SSO users get roles <strong>only</strong> through these mappings (from the SAML <code>groups</code> attribute, the OIDC <code>groups</code> claim or SCIM group membership). Users whose groups map to nothing cannot sign in.</p>
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

        <OidcSection hasMappings={(maps.data?.mappings.length ?? 0) > 0} />

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
