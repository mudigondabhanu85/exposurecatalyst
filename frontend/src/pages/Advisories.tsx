import { Fragment, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, Route, Routes, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime, upload, type Advisory, type AdvisoryTools, type AdvisorySummary, type DistList, type MatrixRow, type Template } from "../api";
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

const TEXT_FIELDS = ["subject", "title", "summary", "business_impact", "remediation", "workaround", "affected_products", "owner_contact", "vuln_type", "owner_actions", "support_actions"] as const;
/** Template components that print a field, so a template using the component counts as using the field. */
const FIELD_COMPONENTS: Record<string, string[]> = {
  owner_actions: ["role_actions"], support_actions: ["role_actions"], vuln_type: ["vulnerability_analysis"],
};

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
                  actions={<Link className="btn-secondary" to="/advisories/templates">Templates</Link>} />
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
  // Message fields auto-save when you leave a field. Saves are queued so a following action (Submit, a matrix
  // change) never overtakes them. The form is re-mounted only when the server changed message fields itself.
  const saving = useRef<Promise<unknown>>(Promise.resolve());
  const [formKey, setFormKey] = useState(0);
  const refreshForm = () => setFormKey((k) => k + 1);
  const call = useMutation({
    mutationFn: async ({ path, method = "POST", body }: { path: string; method?: string; body?: unknown }) => {
      await saving.current.catch(() => undefined);
      return api<Advisory>(`/api/advisories/${id}${path}`, { method, body });
    },
    onSuccess: (a) => { set(a); qc.invalidateQueries({ queryKey: ["advisories"] }); },
  });
  const a = q.data;
  if (q.isError) return <ErrorNote error={q.error} />;
  if (!a) return <LoadingScreen />;
  const editable = a.status === "draft" && can("advisory:create");
  const exportable = (a.status === "approved" || a.status === "sent") && can("advisory:export");

  const saveMessage = (form: HTMLFormElement, all: boolean) => {
    if (!editable) return;
    const saved = qc.getQueryData<Advisory>(key) ?? a;
    const fd = new FormData(form);
    const body: Record<string, unknown> = {};
    for (const k of TEXT_FIELDS) {
      const v = String(fd.get(k) ?? "");
      if (all || v !== (saved[k] ?? "")) body[k] = v;
    }
    const sla = String(fd.get("sla_due_date") || "") || null;
    if (all || sla !== saved.sla_due_date) body.sla_due_date = sla;
    for (const k of ["to_addrs", "cc_addrs", "bcc_addrs"] as const) {
      const v = splitEmails(String(fd.get(k) ?? ""));
      if (all || v.join(",") !== saved[k].join(",")) body[k] = v;
    }
    if (!Object.keys(body).length) return;
    const p = saving.current.catch(() => undefined).then(() => api<Advisory>(`/api/advisories/${id}`, { method: "PATCH", body }));
    saving.current = p;
    p.then((adv) => { set(adv); setNote("Saved — preview updated."); qc.invalidateQueries({ queryKey: ["advisories"] }); },
      (err) => setNote(`Not saved: ${(err as Error).message}`));
  };
  const saveFields = (e: FormEvent<HTMLFormElement>) => { e.preventDefault(); saveMessage(e.currentTarget, true); };
  const tplBody = templates.data?.find((t) => t.id === a.template_id)?.versions.find((v) => v.version === a.template_version)?.body_template;
  const unused = (field: string) => tplBody !== undefined && ![field, ...(FIELD_COMPONENTS[field] ?? [])].some((n) => tplBody.includes(n));
  const exposureTpl = templates.data?.find((t) => t.kind === "exposure_analysis" && t.versions.some((v) => v.status === "approved"));
  const unusedHint = (field: string) => unused(field) && (
    <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-[#5C4200]">
      <span>The email currently uses the “{a.template_name}” template, which doesn't include this section.</span>
      {editable && exposureTpl && exposureTpl.id !== a.template_id && <button type="button" className="underline font-semibold"
        onClick={() => call.mutate({ path: "", method: "PATCH", body: { template_id: exposureTpl.id } }, { onSuccess: () => setNote(`Switched to the ${exposureTpl.name} template.`) })}>
        Use the {exposureTpl.name} template</button>}
    </p>);

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
    to_addrs: [...new Set([...a.to_addrs, ...l.to_addrs])], cc_addrs: [...new Set([...a.cc_addrs, ...l.cc_addrs])], bcc_addrs: [...new Set([...a.bcc_addrs, ...l.bcc_addrs])] } }, { onSuccess: refreshForm });
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
                <button className="btn-secondary" onClick={() => call.mutate({ path: "", method: "PATCH", body: { [k]: v } }, { onSuccess: () => { refreshForm(); setNote(`Applied AI suggestion to ${k.replace("_", " ")} — review it before submitting.`); } })}>Apply</button></div>
                <p className="whitespace-pre-line text-sm">{v}</p></li>))}</ul>
            <AiMeta r={draft.data} />
          </>)}
        </AiBox></div>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="space-y-4">
          <form onSubmit={saveFields} key={`${id}-${formKey}`} onBlur={(e) => saveMessage(e.currentTarget, false)}>
            <Section title="Message" actions={editable && <span className="flex items-center gap-2"><span className="text-xs text-ec-slate">Saves when you leave a field</span><button className="btn-primary">Save</button></span>}>
              <fieldset disabled={!editable} className="space-y-3">
                <div>
                  <label className="label" htmlFor="subject">Subject</label>
                  <div className="flex gap-2"><input id="subject" name="subject" className="input flex-1" defaultValue={a.subject} maxLength={300} required />
                    {editable && <button type="button" className="btn-secondary" title="Rebuild from the template (severity, ID, CVE, product, asset count)" onClick={() => call.mutate({ path: "/subject/regenerate" }, { onSuccess: refreshForm })}>Regenerate</button>}</div>
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
                <div className="grid gap-3 md:grid-cols-2">
                  <div><label className="label" htmlFor="affected_products">Affected products</label><input id="affected_products" name="affected_products" className="input w-full" defaultValue={a.affected_products ?? ""} /></div>
                  <div><label className="label" htmlFor="vuln_type">Vulnerability type<InfoTip text="Prefilled from the CVE's CWE. Shown as “Type” in the vulnerability analysis." /></label><input id="vuln_type" name="vuln_type" className="input w-full" maxLength={300} defaultValue={a.vuln_type ?? ""} placeholder="e.g. Race condition (CWE-362)" />{unusedHint("vuln_type")}</div>
                </div>
                {(["summary", "business_impact", "remediation", "workaround"] as const).map((k) => (
                  <div key={k}><label className="label" htmlFor={k}>{k.replace("_", " ")}</label><textarea id={k} name={k} rows={k === "summary" ? 4 : 3} className="input w-full" defaultValue={a[k] ?? ""} />{unusedHint(k)}</div>))}
                <div className="grid gap-3 md:grid-cols-2">
                  {([["owner_actions", "Risk owner (BISO) actions"], ["support_actions", "Support team actions"]] as const).map(([k, label]) => (
                    <div key={k}><label className="label" htmlFor={k}>{label}<InfoTip text="One action per line; lines starting with “- ” become bullets. Used by the Exposure Analysis template." /></label>
                      <textarea id={k} name={k} rows={5} className="input w-full" defaultValue={a[k] ?? ""} />{unusedHint(k)}</div>))}
                </div>
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
            <ToolMatrix a={a} editable={editable} onChange={(source, body) => call.mutate({ path: `/sources/${encodeURIComponent(source)}`, method: "PUT", body })} />
            <p className="mt-2 text-xs text-ec-slate">Only ticked tools appear in the email, the Excel file and the totals. New advisories start with your enabled integrations; add any other tool you checked manually. “Pull from integrations” refreshes integrated tools and keeps your choices and manual rows.</p>
          </Section>

          <Section title={`Affected assets (${a.assets.length})`}>
            {editable && (<>
              <form onSubmit={addAsset} className="mb-3 grid grid-cols-2 gap-2 md:grid-cols-4">
                <select name="source" className="input" aria-label="Source" required>{a.matrix.map((r) => <option key={r.source}>{r.source}</option>)}</select>
                <input name="hostname" className="input" placeholder="Hostname" aria-label="Hostname" />
                <input name="ip_address" className="input" placeholder="IP address" aria-label="IP address" />
                <input name="resource_id" className="input" placeholder="Cloud resource ID" aria-label="Cloud resource ID" />
                <input name="owner" className="input" placeholder="Owner" aria-label="Owner" />
                <input name="environment" className="input" placeholder="Environment" aria-label="Environment" />
                <input name="business_unit" className="input" placeholder="Division / business unit" aria-label="Division or business unit" />
                <input name="support_group" className="input" placeholder="Support group" aria-label="Support group" />
                <input name="asset_class" className="input" placeholder="Asset class" aria-label="Asset class" />
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
                <thead className="sticky top-0 bg-ec-surface-alt"><tr>{["Source", "Hostname", "IP", "Resource ID", "Owner", "Env", "Support group", "Ref", ""].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
                <tbody>{a.assets.map((x) => (
                  <tr key={x.id} className="border-t border-ec-surface-alt">
                    <td className="td">{x.source}{x.is_manual && <span className="ml-1 text-[10px] font-semibold uppercase text-ec-slate">Manual</span>}</td>
                    <td className="td">{x.hostname}</td><td className="td">{x.ip_address}</td><td className="td break-all">{x.resource_id}</td><td className="td">{x.owner}</td><td className="td">{x.environment}</td><td className="td">{x.support_group}</td><td className="td">{x.source_ref}</td>
                    <td className="td">{editable && <button className="text-red-800 underline" aria-label={`Remove ${x.hostname ?? x.ip_address ?? "asset"}`} onClick={() => call.mutate({ path: `/assets/${x.id}`, method: "DELETE" })}>Remove</button>}</td>
                  </tr>))}
                </tbody></table></div>)}
          </Section>
          <TicketsAndSharing id={id} />
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

interface ActionTarget { id: number; name: string; kind: string; label: string; capability: "create_ticket" | "notify" }
interface ActionRecord { id: number; integration: string; kind: string; label: string; status: string; ref: string | null; url: string | null; error: string | null; created_at: string; created_by: string | null }

const CHECK_VALUES = [["", "—"], ["yes", "Yes"], ["no", "No"]] as const;

function ToolMatrix({ a, editable, onChange }: { a: Advisory; editable: boolean; onChange: (source: string, body: Partial<Pick<MatrixRow, "shown" | "check_available" | "detection_method" | "note" | "manual_count">>) => void }) {
  const tools = useQuery({ queryKey: ["advisory-tools"], queryFn: () => api<AdvisoryTools>("/api/advisory-sources"), enabled: editable });
  const [adding, setAdding] = useState("");
  const methods = tools.data?.detection_methods ?? { vulnerability_check: "Vulnerability check", software_inventory: "Software inventory", asset_inventory: "Asset inventory / CMDB", manual: "Manual analysis" };
  const listed = new Set(a.matrix.map((r) => r.source));
  const suggestions = [...(tools.data?.integrated ?? []), ...(tools.data?.catalog ?? [])].filter((t, i, all) => !listed.has(t) && all.indexOf(t) === i);
  const shownTotal = a.matrix.filter((r) => r.shown).length;
  const add = (e: FormEvent) => { e.preventDefault(); const name = adding.trim(); if (name) { onChange(name, { shown: true }); setAdding(""); } };
  return (<>
    <div className="overflow-x-auto"><table className="min-w-full text-sm">
      <thead className="bg-ec-surface-alt"><tr>
        <th className="th">In email</th><th className="th">Tool</th><th className="th">Check available<InfoTip text="Does this tool have a detection for the CVE? “Yes” with 0 assets reads as “checks available, no vulnerable instances”." /></th>
        <th className="th">Validated</th><th className="th text-right">Assets</th><th className="th">Detection method</th><th className="th">Last checked</th><th className="th">Manual count</th>
      </tr></thead>
      <tbody>{a.matrix.map((r) => (<Fragment key={r.source}>
        <tr className={`border-t border-ec-surface-alt ${r.shown ? "" : "opacity-60"}`}>
          <td className="td"><input type="checkbox" aria-label={`Show ${r.source} in the email`} checked={r.shown} disabled={!editable}
            onChange={(e) => { if (!e.target.checked && r.asset_count > 0 && !window.confirm(`${r.source} has ${r.asset_count} affected asset(s). Hide it? Its assets are then left out of the email, the Excel file and the totals.`)) return; onChange(r.source, { shown: e.target.checked }); }} /></td>
          <td className="td">{r.source}{r.manual && <span className="ml-1 rounded-sm bg-ec-surface-alt px-1 text-[10px] font-semibold uppercase">Manual</span>}{!r.shown && <span className="ml-1 text-[10px] font-semibold uppercase text-ec-slate">Hidden</span>}</td>
          <td className="td">{editable ? (
            <select aria-label={`${r.source} check available`} className="input" value={r.check_available === null ? "" : r.check_available ? "yes" : "no"}
              onChange={(e) => onChange(r.source, { check_available: e.target.value === "" ? null : e.target.value === "yes" })}>
              {CHECK_VALUES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>) : (r.check_available === null ? "—" : r.check_available ? "Yes" : "No")}</td>
          <td className={`td ${r.validated === "Yes" ? "font-bold" : "text-ec-slate"}`}>{r.validated}</td>
          <td className="td text-right">{r.validated === "Not Integrated" ? "—" : r.asset_count}</td>
          <td className="td">{editable ? (
            <select aria-label={`${r.source} detection method`} className="input" value={r.detection_method ?? ""}
              onChange={(e) => onChange(r.source, { detection_method: (e.target.value || null) as MatrixRow["detection_method"] })}>
              <option value="">—</option>{Object.entries(methods).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>) : (r.detection_method ? methods[r.detection_method] : "—")}</td>
          <td className="td text-xs">{fmtDateTime(r.last_checked)}</td>
          <td className="td">{editable && <input aria-label={`${r.source} manual count`} type="number" min={0} className="input w-20" defaultValue={r.manual_count ?? ""}
            onBlur={(e) => { const v = e.target.value === "" ? null : Number(e.target.value); if (v !== r.manual_count) onChange(r.source, { manual_count: v }); }} />}</td>
        </tr>
        {r.shown && (editable || r.note || r.finding) && <tr><td />
          <td className="td pt-0" colSpan={7}>{editable
            ? <input aria-label={`${r.source} note for the email`} className="input w-full text-xs" maxLength={2000} defaultValue={r.note ?? ""} placeholder={r.finding || "Note for the email (optional)"}
                onBlur={(e) => { if (e.target.value.trim() !== (r.note ?? "")) onChange(r.source, { note: e.target.value }); }} />
            : <span className="text-xs text-ec-slate">{r.note || r.finding}</span>}</td></tr>}
      </Fragment>))}
      {a.matrix.length === 0 && <tr><td className="td text-ec-slate" colSpan={8}>No tools yet. Add the tools you checked for this CVE below, or ask an admin to enable integrations.</td></tr>}
      </tbody>
      <tfoot><tr className="border-t-2 border-ec-border"><td className="td font-bold" colSpan={4}>Total unique affected assets<InfoTip k="affected_assets" /> <span className="text-xs font-normal text-ec-slate">({shownTotal} tool{shownTotal === 1 ? "" : "s"} in email)</span></td><td className="td text-right font-bold">{a.total_unique_assets}</td><td colSpan={3} /></tr></tfoot>
    </table></div>
    {editable && <form onSubmit={add} className="mt-2 flex flex-wrap items-center gap-2 text-sm">
      <input list="advisory-tool-list" className="input" aria-label="Add a tool" placeholder="Add a tool (e.g. Tanium)" maxLength={64} value={adding} onChange={(e) => setAdding(e.target.value)} />
      <datalist id="advisory-tool-list">{suggestions.map((t) => <option key={t} value={t} />)}</datalist>
      <button className="btn-secondary" disabled={!adding.trim()}>Add tool</button>
    </form>}
  </>);
}

function TicketsAndSharing({ id }: { id: string }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["advisory-actions", id], queryFn: () => api<{ allowed: boolean; status: string; available: ActionTarget[]; history: ActionRecord[] }>(`/api/advisories/${id}/actions`) });
  const run = useMutation({
    mutationFn: (integration_id: number) => api<ActionRecord>(`/api/advisories/${id}/actions`, { method: "POST", body: { integration_id } }),
    onSettled: () => { qc.invalidateQueries({ queryKey: ["advisory-actions", id] }); qc.invalidateQueries({ queryKey: ["advisory-history", id] }); },
  });
  const d = q.data;
  if (!d || (d.available.length === 0 && d.history.length === 0)) return null;
  return (
    <Section title="Tickets & sharing" tip="Create a ticket in Jira or ServiceNow, or post to Slack / Teams, from an approved advisory. Configure targets in Settings → Integrations.">
      <ErrorNote error={q.error ?? run.error} />
      {d.available.length > 0 && (
        d.allowed && can("advisory:send") ? (
          <div className="mb-3 flex flex-wrap gap-2">
            {d.available.map((t) => (
              <button key={t.id} className="btn-secondary" disabled={run.isPending} onClick={() => run.mutate(t.id)}>
                {t.capability === "create_ticket" ? "Create ticket" : "Post"} · {t.name}
              </button>
            ))}
          </div>
        ) : (
          <p className="mb-3 text-sm text-ec-slate">{d.allowed ? "You need the advisory:send permission to create tickets or post." : "Available once the advisory is approved."}</p>
        )
      )}
      {d.history.length > 0 && (
        <ul className="space-y-1 text-xs">{d.history.map((h) => (
          <li key={h.id}>
            <span className="text-ec-slate">{fmtDateTime(h.created_at)}</span> · <strong>{h.integration}</strong> ·{" "}
            {h.status === "ok"
              ? (h.url ? <a className="link" href={h.url} target="_blank" rel="noopener noreferrer">{h.ref} ↗</a> : <span>{h.ref === "posted" ? "posted" : h.ref}</span>)
              : <span className="text-red-800">failed: {h.error}</span>}
            {h.created_by && <span className="text-ec-slate"> · {h.created_by}</span>}
          </li>))}
        </ul>
      )}
    </Section>
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
