import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, Route, Routes, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime, upload, type Advisory, type AdvisorySummary, type DistList, type Template } from "../api";
import { useAuth } from "../auth";
import { InfoTip } from "../help";
import { EmptyState, ErrorNote, PageHeader, SeverityBadge } from "../components/ui";
import { Forbidden, LoadingScreen } from "../components/StatusScreen";
import TemplatesPage from "./Templates";
import { AiBox, AiMeta, useAi } from "../components/Ai";

const STATUS_STYLE: Record<string, string> = {
  draft: "bg-ec-surface-alt text-ec-navy",
  in_review: "bg-[#FFF4CC] text-[#5C4200]",
  approved: "bg-emerald-100 text-emerald-900",
  sent: "bg-ec-navy text-white",
  cancelled: "bg-ec-surface-alt text-ec-slate line-through",
};
export const StatusBadge = ({ status }: { status: string }) => (
  <span className={`rounded-sm px-2 py-0.5 text-xs font-semibold capitalize ${STATUS_STYLE[status] ?? ""}`}>{status.replace("_", " ")}</span>
);

const ADVISORY_PERMS = ["advisory:create", "advisory:approve", "advisory:send", "advisory:export"];

export default function AdvisoriesRoutes() {
  const { can } = useAuth();
  if (!ADVISORY_PERMS.some(can) && !can("template:manage")) return <Forbidden message="Advisories require an advisory or template permission." />;
  return (
    <Routes>
      <Route index element={<AdvisoryList />} />
      <Route path="new" element={<NewAdvisory />} />
      <Route path="templates" element={<TemplatesPage />} />
      <Route path=":id" element={<AdvisoryEditor />} />
    </Routes>
  );
}

function AdvisoryList() {
  const { can } = useAuth();
  const [status, setStatus] = useState("");
  const q = useQuery({ queryKey: ["advisories", status], queryFn: () => api<AdvisorySummary[]>("/api/advisories", { query: { status } }), enabled: ADVISORY_PERMS.some(can) });
  return (
    <>
      <PageHeader title="Advisory Email Generator" helpId="advisories" subtitle="Draft → review → approve → send, with a full audit trail"
                  actions={<Link className="btn-secondary" to="templates">Templates</Link>} />
      <div className="mb-3 flex items-center gap-2">
        <label className="label mb-0" htmlFor="st">Status</label>
        <select id="st" className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All</option>{["draft", "in_review", "approved", "sent", "cancelled"].map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
        </select>
      </div>
      <ErrorNote error={q.error} />
      {q.data?.length === 0 ? (
        <EmptyState title="No advisories yet" why="Open a CVE in CVE Intelligence and click “Create Advisory Email” to start a draft." fix={{ label: "Go to CVE Intelligence", to: "/cves" }} />
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="min-w-full text-sm">
            <thead className="bg-ec-surface-alt"><tr><th className="th">Advisory ID<InfoTip k="advisory_id" /></th><th className="th">CVE</th><th className="th">Severity</th><th className="th">Status</th><th className="th">Subject</th><th className="th">Author</th><th className="th">Updated</th></tr></thead>
            <tbody>{q.data?.map((a) => (
              <tr key={a.id} className="border-t border-ec-surface-alt">
                <td className="td whitespace-nowrap font-mono"><Link className="link" to={String(a.id)}>{a.advisory_id}</Link></td>
                <td className="td font-mono">{a.cve_id}</td><td className="td"><SeverityBadge severity={a.severity} /></td>
                <td className="td"><StatusBadge status={a.status} /></td><td className="td max-w-md truncate">{a.subject}</td>
                <td className="td">{a.created_by}</td><td className="td whitespace-nowrap text-xs">{fmtDateTime(a.updated_at)}</td>
              </tr>))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function NewAdvisory() {
  const [params] = useSearchParams();
  const nav = useNavigate();
  const { can } = useAuth();
  const cve = params.get("cve") ?? "";
  const started = useRef(false);
  const create = useMutation({ mutationFn: () => api<Advisory>("/api/advisories", { method: "POST", body: { cve_id: cve } }),
                               onSuccess: (a) => nav(`/advisories/${a.id}`, { replace: true }) });
  useEffect(() => { if (cve && can("advisory:create") && !started.current) { started.current = true; create.mutate(); } }, [cve, can, create]);
  if (!can("advisory:create")) return <Forbidden message="Creating advisories requires the advisory:create permission." />;
  if (!cve) return <EmptyState title="Pick a CVE first" why="Advisories start from a CVE so details are pre-filled." fix={{ label: "Go to CVE Intelligence", to: "/cves" }} />;
  return create.isError ? <><PageHeader title="New advisory" helpId="advisories" /><ErrorNote error={create.error} /></> : <LoadingScreen />;
}

// ---- Editor ---------------------------------------------------------------------------------------

function Section({ title, tip, children, actions }: { title: string; tip?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      <div className="mb-3 flex items-center justify-between gap-2"><h2 className="flex items-center gap-1 font-heading font-bold">{title}{tip && <InfoTip k={tip} />}</h2>{actions}</div>
      {children}
    </section>
  );
}

const splitEmails = (s: string) => s.split(/[,;\s]+/).map((x) => x.trim()).filter(Boolean);

function ConfirmSend({ adv, onCancel, onConfirm, busy }: { adv: Advisory; onCancel: () => void; onConfirm: () => void; busy: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { ref.current?.focus(); const k = (e: KeyboardEvent) => e.key === "Escape" && onCancel(); document.addEventListener("keydown", k); return () => document.removeEventListener("keydown", k); }, [onCancel]);
  const n = new Set([...adv.to_addrs, ...adv.cc_addrs, ...adv.bcc_addrs]).size;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div ref={ref} tabIndex={-1} role="alertdialog" aria-modal="true" aria-labelledby="cs-t" aria-describedby="cs-d" className="w-full max-w-lg rounded-md bg-white p-5 shadow-xl focus:outline-none">
        <h2 id="cs-t" className="font-heading text-lg font-bold">Send {adv.advisory_id}?</h2>
        <div id="cs-d" className="mt-2 space-y-1 text-sm text-ec-slate">
          <p><strong className="text-ec-navy">Subject:</strong> {adv.subject}</p>
          <p><strong className="text-ec-navy">To:</strong> {adv.to_addrs.join(", ")}</p>
          {adv.cc_addrs.length > 0 && <p><strong className="text-ec-navy">CC:</strong> {adv.cc_addrs.join(", ")}</p>}
          {adv.bcc_addrs.length > 0 && <p><strong className="text-ec-navy">BCC:</strong> {adv.bcc_addrs.join(", ")}</p>}
          <p>{n} recipient(s) · Excel attachment with {adv.total_unique_assets} unique asset(s). This cannot be undone.</p>
        </div>
        <div className="mt-4 flex justify-end gap-2">
          <button className="btn-secondary" onClick={onCancel}>Cancel</button>
          <button className="btn-primary" onClick={onConfirm} disabled={busy}>{busy ? "Sending…" : "Send now"}</button>
        </div>
      </div>
    </div>
  );
}

function AdvisoryEditor() {
  const { id = "" } = useParams();
  const { can, me } = useAuth();
  const qc = useQueryClient();
  const key = ["advisory", id];
  const q = useQuery({ queryKey: key, queryFn: () => api<Advisory>(`/api/advisories/${id}`) });
  const templates = useQuery({ queryKey: ["templates"], queryFn: () => api<Template[]>("/api/templates") });
  const lists = useQuery({ queryKey: ["dist-lists"], queryFn: () => api<DistList[]>("/api/distribution-lists") });
  const [previewKey, setPreviewKey] = useState(0);
  const [note, setNote] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const aiOn = useAi();
  const draft = useMutation({ mutationFn: () => api<{ suggestion: Record<string, string>; provider: string; model: string; redacted_values: number; fallbacks: string[]; note: string }>(`/api/ai/advisories/${id}/draft`, { method: "POST" }) });
  const set = (a: Advisory) => { qc.setQueryData(key, a); setPreviewKey((k) => k + 1); };
  const call = useMutation({
    mutationFn: ({ path, method = "POST", body }: { path: string; method?: string; body?: unknown }) => api<Advisory>(`/api/advisories/${id}${path}`, { method, body }),
    onSuccess: (a) => { set(a); qc.invalidateQueries({ queryKey: ["advisories"] }); },
  });
  const a = q.data;
  if (q.isError) return <ErrorNote error={q.error} />;
  if (!a) return <LoadingScreen />;
  const editable = a.status === "draft" && can("advisory:create");
  const exportable = (a.status === "approved" || a.status === "sent") && can("advisory:export");

  const saveFields = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const body: Record<string, unknown> = {};
    for (const k of ["subject", "title", "summary", "business_impact", "remediation", "workaround", "affected_products", "owner_contact"]) body[k] = String(fd.get(k) ?? "");
    body.sla_due_date = fd.get("sla_due_date") || null;
    for (const k of ["to_addrs", "cc_addrs", "bcc_addrs"]) body[k] = splitEmails(String(fd.get(k) ?? ""));
    call.mutate({ path: "", method: "PATCH", body }, { onSuccess: () => setNote("Saved") });
  };

  const copyForOutlook = async () => {
    try {
      const html = await api<string>(`/api/advisories/${id}/export/clipboard`);
      // Rich HTML on the clipboard (logo as data URI) so formatting survives paste into Outlook.
      await navigator.clipboard.write([new ClipboardItem({ "text/html": new Blob([html], { type: "text/html" }), "text/plain": new Blob([a.subject], { type: "text/plain" }) })]);
      setNote("Copied — paste into a new Outlook message (Ctrl/Cmd+V). Attach the Excel file separately.");
    } catch (err) { setNote(`Copy failed: ${(err as Error).message}`); }
  };

  const onUpload = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    try {
      const r = await upload<{ imported: number; errors: string[]; advisory: Advisory }>(`/api/advisories/${id}/assets/upload`, new FormData(form));
      set(r.advisory); form.reset();
      setNote(`Imported ${r.imported} row(s).${r.errors.length ? ` ${r.errors.length} skipped: ${r.errors.slice(0, 3).join("; ")}` : ""}`);
    } catch (err) { setNote(`Upload failed: ${(err as Error).message}`); }
  };

  const addAsset = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const fd = new FormData(form);
    const body: Record<string, unknown> = {};
    for (const [k, v] of fd.entries()) if (v) body[k] = v;
    call.mutate({ path: "/assets", body }, { onSuccess: () => form.reset() });
  };

  const applyList = (l: DistList) => call.mutate({ path: "", method: "PATCH", body: {
    to_addrs: [...new Set([...a.to_addrs, ...l.to_addrs])], cc_addrs: [...new Set([...a.cc_addrs, ...l.cc_addrs])], bcc_addrs: [...new Set([...a.bcc_addrs, ...l.bcc_addrs])] } });
  const saveList = async () => {
    const name = window.prompt("Name for this distribution list");
    if (!name) return;
    try { await api("/api/distribution-lists", { method: "POST", body: { name, to_addrs: a.to_addrs, cc_addrs: a.cc_addrs, bcc_addrs: a.bcc_addrs } }); qc.invalidateQueries({ queryKey: ["dist-lists"] }); setNote(`Saved list “${name}”`); }
    catch (err) { setNote((err as Error).message); }
  };

  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-sm"><Link className="link" to="/advisories">Advisories</Link> / {a.advisory_id}</nav>
      <PageHeader title={a.advisory_id} helpId="advisory-editor" subtitle={`${a.cve_id} · ${a.template_name} template v${a.template_version} · by ${a.created_by ?? "—"}`}
        actions={<span className="flex items-center gap-2"><SeverityBadge severity={a.severity} /><StatusBadge status={a.status} /></span>} />
      {a.review_comment && <p role="status" className="mb-3 rounded-sm bg-[#FFF4CC] px-3 py-2 text-sm text-[#5C4200]"><strong>Reviewer comment:</strong> {a.review_comment}</p>}
      {note && <p role="status" className="mb-3 rounded-sm bg-ec-surface-alt px-3 py-2 text-sm">{note} <button className="ml-2 text-xs underline" onClick={() => setNote(null)}>dismiss</button></p>}
      <ErrorNote error={call.error} />

      {/* Workflow & delivery bar */}
      <div className="card mb-4 flex flex-wrap items-center gap-2 py-3">
        {editable && <button className="btn-primary" onClick={() => call.mutate({ path: "/submit" })}>Submit for review</button>}
        {a.status === "in_review" && can("advisory:approve") && me?.username !== a.created_by && (<>
          <button className="btn-primary" onClick={() => call.mutate({ path: "/approve", body: { comment: null } })}>Approve</button>
          <button className="btn-secondary" onClick={() => { const c = window.prompt("What needs to change?"); if (c) call.mutate({ path: "/reject", body: { comment: c } }); }}>Request changes</button>
        </>)}
        {a.status === "in_review" && me?.username === a.created_by && <span className="text-sm text-ec-slate">Waiting for another approver (you authored this advisory).</span>}
        {a.status === "approved" && can("advisory:send") && <button className="btn-primary" onClick={() => setConfirming(true)}>Send via SMTP…</button>}
        {exportable && (<>
          <button className="btn-secondary" onClick={copyForOutlook}>Copy for Outlook</button>
          <a className="btn-secondary" href={`/api/advisories/${id}/export/eml`}>Download .eml</a>
          <a className="btn-secondary" href={`/api/advisories/${id}/export/xlsx`}>Excel</a>
          <a className="btn-secondary" href={`/api/advisories/${id}/export/html`}>HTML</a>
          <a className="btn-secondary" href={`/api/advisories/${id}/export/pdf`}>PDF</a>
        </>)}
        {!exportable && a.status !== "cancelled" && <span className="text-xs text-ec-slate">Exports and sending unlock after approval.</span>}
        {["draft", "in_review", "approved"].includes(a.status) && can("advisory:create") && <button className="btn-secondary ml-auto" onClick={() => window.confirm("Cancel this advisory?") && call.mutate({ path: "/cancel" })}>Cancel advisory</button>}
      </div>
      {confirming && <ConfirmSend adv={a} busy={call.isPending} onCancel={() => setConfirming(false)} onConfirm={() => call.mutate({ path: "/send", body: { confirm: true } }, { onSettled: () => setConfirming(false), onSuccess: () => setNote("Sent.") })} />}

      {editable && aiOn && (
        <div className="mb-4"><AiBox title="Draft with AI" actions={<button className="btn-secondary" disabled={draft.isPending} onClick={() => draft.mutate()}>{draft.isPending ? "Drafting…" : draft.data ? "Redraft" : "Draft sections"}</button>}>
          <ErrorNote error={draft.error} />
          {!draft.data && !draft.isPending && <p className="text-sm text-ec-slate">Suggests subject, summary, business impact, remediation and workaround from the CVE and your exposure. Nothing is saved until you apply a suggestion — and every advisory still needs approval.</p>}
          {draft.data && (<>
            <ul className="space-y-3">{Object.entries(draft.data.suggestion).map(([k, v]) => (
              <li key={k} className="rounded-md bg-ec-surface-alt p-3"><div className="mb-1 flex items-center justify-between"><span className="label mb-0">{k.replace("_", " ")}</span>
                <button className="btn-secondary" onClick={() => call.mutate({ path: "", method: "PATCH", body: { [k]: v } }, { onSuccess: () => setNote(`Applied AI suggestion to ${k.replace("_", " ")} — review it before submitting.`) })}>Apply</button></div>
                <p className="whitespace-pre-line text-sm">{v}</p></li>))}</ul>
            <AiMeta r={draft.data} />
          </>)}
        </AiBox></div>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="space-y-4">
          <form onSubmit={saveFields} key={a.updated_at}>
            <Section title="Message" actions={editable && <button className="btn-primary">Save</button>}>
              <fieldset disabled={!editable} className="space-y-3">
                <div>
                  <label className="label" htmlFor="subject">Subject</label>
                  <div className="flex gap-2"><input id="subject" name="subject" className="input flex-1" defaultValue={a.subject} maxLength={300} required />
                    {editable && <button type="button" className="btn-secondary" title="Rebuild from the template (severity, ID, CVE, product, asset count)" onClick={() => call.mutate({ path: "/subject/regenerate" })}>Regenerate</button>}</div>
                </div>
                <div className="grid gap-3 md:grid-cols-3">
                  {(["to_addrs", "cc_addrs", "bcc_addrs"] as const).map((k) => (
                    <div key={k}><label className="label" htmlFor={k}>{k.split("_")[0].toUpperCase()}</label>
                      <textarea id={k} name={k} rows={2} className="input w-full" defaultValue={a[k].join(", ")} placeholder="name@example.com, …" /></div>))}
                </div>
                {editable && <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="label mb-0">Distribution lists</span>
                  {lists.data?.map((l) => <button type="button" key={l.id} className="btn-secondary" onClick={() => applyList(l)}>+ {l.name}</button>)}
                  <button type="button" className="text-xs underline" onClick={saveList}>Save current recipients as a list</button>
                </div>}
                <div className="grid gap-3 md:grid-cols-2">
                  <div><label className="label" htmlFor="title">Title</label><input id="title" name="title" className="input w-full" defaultValue={a.title ?? ""} /></div>
                  <div><label className="label" htmlFor="tpl">Template</label>
                    <select id="tpl" className="input w-full" value={a.template_id} onChange={(e) => call.mutate({ path: "", method: "PATCH", body: { template_id: Number(e.target.value) } })}>
                      {templates.data?.filter((t) => t.versions.some((v) => v.status === "approved")).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                    </select></div>
                  <div><label className="label" htmlFor="owner_contact">Owner / contact</label><input id="owner_contact" name="owner_contact" className="input w-full" defaultValue={a.owner_contact ?? ""} placeholder="SecOps · secops@example.com" /></div>
                  <div><label className="label" htmlFor="sla_due_date">Remediation due (SLA)<InfoTip text="Defaults to the CISA KEV due date, otherwise Critical 7 / High 14 / Medium 30 / Low 90 days." /></label><input id="sla_due_date" name="sla_due_date" type="date" className="input w-full" defaultValue={a.sla_due_date ?? ""} /></div>
                </div>
                <div><label className="label" htmlFor="affected_products">Affected products</label><input id="affected_products" name="affected_products" className="input w-full" defaultValue={a.affected_products ?? ""} /></div>
                {(["summary", "business_impact", "remediation", "workaround"] as const).map((k) => (
                  <div key={k}><label className="label" htmlFor={k}>{k.replace("_", " ")}</label><textarea id={k} name={k} rows={k === "summary" ? 4 : 3} className="input w-full" defaultValue={a[k] ?? ""} /></div>))}
              </fieldset>
            </Section>
          </form>

          <Section title="Asset validation matrix" tip="validated" actions={editable && (
            <button className="btn-secondary" disabled={call.isPending} onClick={async () => {
              try {
                const r = await api<{ results: { source: string; status: string; assets: number; truncated: boolean; error: string | null }[]; advisory: Advisory }>(`/api/advisories/${id}/assets/pull`, { method: "POST", body: { force: false } });
                set(r.advisory);
                setNote(r.results.length ? r.results.map((x) => `${x.source}: ${x.status === "ok" ? `${x.assets}${x.truncated ? "+" : ""} asset(s)` : `${x.status}${x.error ? ` — ${x.error}` : ""}`}`).join(" · ") : "No integrations are enabled — ask an admin to configure Settings → Integrations.");
              } catch (err) { setNote(`Pull failed: ${(err as Error).message}`); }
            }}>Pull from integrations</button>)}>
            <table className="min-w-full text-sm">
              <thead className="bg-ec-surface-alt"><tr><th className="th">Source</th><th className="th">Validated</th><th className="th text-right">Assets</th><th className="th">Last checked</th><th className="th">Manual count</th></tr></thead>
              <tbody>{a.matrix.map((r) => (
                <tr key={r.source} className="border-t border-ec-surface-alt">
                  <td className="td">{r.source}{r.manual && <span className="ml-1 rounded-sm bg-ec-surface-alt px-1 text-[10px] font-semibold uppercase">Manual</span>}</td>
                  <td className={`td ${r.validated === "Yes" ? "font-bold" : "text-ec-slate"}`}>{r.validated}</td>
                  <td className="td text-right">{r.validated === "Not Integrated" ? "—" : r.asset_count}</td>
                  <td className="td text-xs">{fmtDateTime(r.last_checked)}</td>
                  <td className="td">{editable && <input aria-label={`${r.source} manual count`} type="number" min={0} className="input w-20" defaultValue={r.manual_count ?? ""}
                    onBlur={(e) => { const v = e.target.value === "" ? null : Number(e.target.value); if (v !== r.manual_count) call.mutate({ path: `/sources/${encodeURIComponent(r.source)}`, method: "PUT", body: { manual_count: v } }); }} />}</td>
                </tr>))}
              </tbody>
              <tfoot><tr className="border-t-2 border-ec-border"><td className="td font-bold" colSpan={2}>Total unique affected assets<InfoTip k="affected_assets" /></td><td className="td text-right font-bold">{a.total_unique_assets}</td><td colSpan={2} /></tr></tfoot>
            </table>
            <p className="mt-2 text-xs text-ec-slate">“Pull from integrations” queries every enabled tool and replaces integration rows (manual rows are kept). Manual counts and rows are labelled “Manual” in the email and Excel.</p>
          </Section>

          <Section title={`Affected assets (${a.assets.length})`}>
            {editable && (<>
              <form onSubmit={addAsset} className="mb-3 grid grid-cols-2 gap-2 md:grid-cols-4">
                <select name="source" className="input" aria-label="Source" required defaultValue="Qualys">{a.matrix.map((r) => <option key={r.source}>{r.source}</option>)}</select>
                <input name="hostname" className="input" placeholder="Hostname" aria-label="Hostname" />
                <input name="ip_address" className="input" placeholder="IP address" aria-label="IP address" />
                <input name="resource_id" className="input" placeholder="Cloud resource ID" aria-label="Cloud resource ID" />
                <input name="owner" className="input" placeholder="Owner" aria-label="Owner" />
                <input name="environment" className="input" placeholder="Environment" aria-label="Environment" />
                <input name="source_ref" className="input" placeholder="Plugin / QID / ID" aria-label="Plugin, QID or ID" />
                <button className="btn-primary">Add asset</button>
              </form>
              <form onSubmit={onUpload} className="mb-3 flex flex-wrap items-center gap-2 text-sm">
                <input type="file" name="file" accept=".csv,.xlsx" required aria-label="CSV or XLSX file" />
                <select name="default_source" className="input" aria-label="Source for rows without a Source column">{a.matrix.map((r) => <option key={r.source}>{r.source}</option>)}</select>
                <button className="btn-secondary">Upload CSV/XLSX</button>
              </form>
            </>)}
            {a.assets.length === 0 ? <p className="text-sm text-ec-slate">No asset rows yet.</p> : (
              <div className="max-h-80 overflow-auto"><table className="min-w-full text-xs">
                <thead className="sticky top-0 bg-ec-surface-alt"><tr>{["Source", "Hostname", "IP", "Resource ID", "Owner", "Env", "Ref", ""].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
                <tbody>{a.assets.map((x) => (
                  <tr key={x.id} className="border-t border-ec-surface-alt">
                    <td className="td">{x.source}{x.is_manual && <span className="ml-1 text-[10px] font-semibold uppercase text-ec-slate">Manual</span>}</td>
                    <td className="td">{x.hostname}</td><td className="td">{x.ip_address}</td><td className="td break-all">{x.resource_id}</td><td className="td">{x.owner}</td><td className="td">{x.environment}</td><td className="td">{x.source_ref}</td>
                    <td className="td">{editable && <button className="text-red-800 underline" aria-label={`Remove ${x.hostname ?? x.ip_address ?? "asset"}`} onClick={() => call.mutate({ path: `/assets/${x.id}`, method: "DELETE" })}>Remove</button>}</td>
                  </tr>))}
                </tbody></table></div>)}
          </Section>
          <History id={id} />
        </div>

        <Section title="Preview" actions={<span className="text-xs text-ec-slate">Exactly as recipients will see it</span>}>
          {/* Server-rendered email in a sandboxed iframe (no scripts; its own restrictive CSP). */}
          <iframe key={previewKey} title={`Email preview for ${a.advisory_id}`} src={`/api/advisories/${id}/preview`} sandbox="" className="h-[1100px] w-full rounded-sm border border-ec-border bg-white" />
        </Section>
      </div>
    </>
  );
}

function History({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["advisory-history", id], queryFn: () => api<{ at: string; actor: string | null; action: string; details: Record<string, unknown> }[]>(`/api/advisories/${id}/history`), refetchInterval: 15_000 });
  return (
    <Section title="Audit trail">
      <ol className="space-y-1 text-xs">{q.data?.map((h, i) => (
        <li key={i}><span className="text-ec-slate">{fmtDateTime(h.at)}</span> · <strong>{h.actor ?? "system"}</strong> · {h.action.replace("advisory.", "")}
          {h.action === "advisory.sent" && <span className="text-ec-slate"> → {[...(h.details.to as string[] ?? []), ...(h.details.cc as string[] ?? [])].join(", ")}</span>}
          {h.action === "advisory.exported" && <span className="text-ec-slate"> ({String(h.details.format)})</span>}</li>))}
      </ol>
    </Section>
  );
}
