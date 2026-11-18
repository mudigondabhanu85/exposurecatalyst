import { useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime, upload } from "../api";
import { useAuth } from "../auth";
import { ErrorNote } from "./ui";

export interface IntelItem {
  id: number; subscription_id: number; source: string; vendor: string; kind: string; title: string; cve_ids: string[];
  summary: string | null; description: string | null; severity: string | null; exploited: boolean | null; references: string[];
  url: string | null; published_at: string | null; tags: string[]; tlp: string; analyst_notes: string | null; is_manual: boolean;
  attachments: { id: number; filename: string; size: number }[];
}
interface Source { id: number; name: string; vendor: string; source_type: string; default_tlp: string }

const TLP_STYLE: Record<string, string> = {
  CLEAR: "bg-white text-ec-navy border border-ec-border", GREEN: "bg-emerald-100 text-emerald-900",
  AMBER: "bg-amber-100 text-amber-950", "AMBER+STRICT": "bg-amber-200 text-amber-950", RED: "bg-red-100 text-red-900",
};

/** Subscriptions screens render only when features.subscriptions is on (otherwise nothing changes). */
export function useSubscriptionsOn(): boolean {
  const q = useQuery({ queryKey: ["subscriptions-status"], staleTime: 600_000,
                       queryFn: () => api<{ enabled: boolean }>("/api/subscriptions/status") });
  return !!q.data?.enabled;
}

export function TlpBadge({ tlp }: { tlp: string }) {
  return <span className={`rounded-sm px-1.5 py-0.5 text-[10px] font-semibold ${TLP_STYLE[tlp] ?? ""}`}>TLP:{tlp}</span>;
}

export function IntelList({ items, empty }: { items: IntelItem[] | undefined; empty: string }) {
  if (!items) return null;
  if (items.length === 0) return <p className="text-sm text-ec-slate">{empty}</p>;
  return (
    <ul className="space-y-3">
      {items.map((i) => (
        <li key={i.id} className="border-t border-ec-surface-alt pt-2 text-sm first:border-t-0 first:pt-0">
          <div className="flex flex-wrap items-center gap-1.5 text-xs text-ec-slate">
            <span className="font-semibold text-ec-navy">{i.source}</span><TlpBadge tlp={i.tlp} />
            {i.severity && <span>{i.severity}</span>}
            {i.exploited && <span className="rounded-sm bg-ec-navy px-1.5 py-0.5 font-semibold text-white">Exploited</span>}
            {i.published_at && <span>{fmtDateTime(i.published_at)}</span>}
          </div>
          <div className="font-medium">{i.url ? <a className="link" href={i.url} target="_blank" rel="noopener noreferrer nofollow">{i.title}</a> : i.title}</div>
          {i.summary && <p className="text-ec-slate">{i.summary}</p>}
          {i.cve_ids.length > 0 && <p className="text-xs text-ec-slate">{i.cve_ids.slice(0, 8).join(", ")}</p>}
          {i.analyst_notes && <p className="mt-1 rounded-sm bg-ec-surface-alt px-2 py-1 text-xs"><strong>Analyst notes:</strong> {i.analyst_notes}</p>}
          {i.attachments.length > 0 && <p className="text-xs">{i.attachments.map((a) => <a key={a.id} className="link mr-2" href={`/api/subscriptions/attachments/${a.id}`}>{a.filename}</a>)}</p>}
        </li>
      ))}
    </ul>
  );
}

function useSources() {
  return useQuery({ queryKey: ["intel-sources"], queryFn: () => api<Source[]>("/api/subscriptions/sources") });
}

export function ManualIntelForm({ cveId, onDone }: { cveId?: string; onDone?: () => void }) {
  const qc = useQueryClient();
  const sources = useSources();
  const [files, setFiles] = useState<FileList | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault(); setErr(null); setBusy(true);
    const form = e.currentTarget;
    const fd = new FormData(form);
    const g = (k: string) => String(fd.get(k) ?? "").trim();
    try {
      const item = await api<IntelItem>("/api/subscriptions/intel", { method: "POST", body: {
        subscription_id: Number(g("subscription_id")), kind: g("kind"), title: g("title") || null,
        cve_ids: g("cve_ids").split(/[\s,]+/).filter(Boolean), summary: g("summary") || null, description: g("description") || null,
        severity: g("severity") || null, exploited: g("exploited") === "" ? null : g("exploited") === "yes",
        url: g("url") || null, tlp: g("tlp") || null, analyst_notes: g("notes") || null, tags: g("tags").split(",").map((t) => t.trim()).filter(Boolean) } });
      for (const f of Array.from(files ?? [])) {
        const a = new FormData(); a.append("file", f);
        await upload(`/api/subscriptions/intel/${item.id}/attachments`, a);
      }
      form.reset(); setFiles(null);
      qc.invalidateQueries({ queryKey: ["intel"] });
      onDone?.();
    } catch (x) { setErr(x); } finally { setBusy(false); }
  };
  if (sources.data && sources.data.length === 0) return <p className="text-sm text-ec-slate">An administrator must first add a subscription (Settings → Integrations → Threat Intel & News Subscriptions; use type “Manual” for portal / PDF / email sources).</p>;
  return (
    <form onSubmit={submit} className="grid gap-2 md:grid-cols-2">
      <div><label className="label" htmlFor="mi-sub">Source subscription</label>
        <select id="mi-sub" name="subscription_id" className="input w-full" required>{sources.data?.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.vendor})</option>)}</select></div>
      <div><label className="label" htmlFor="mi-kind">Type</label>
        <select id="mi-kind" name="kind" className="input w-full" defaultValue={cveId ? "cve" : "news"}><option value="cve">CVE intel</option><option value="advisory">Advisory</option><option value="news">News / report</option></select></div>
      <div><label className="label" htmlFor="mi-cves">CVE IDs</label><input id="mi-cves" name="cve_ids" className="input w-full" defaultValue={cveId ?? ""} placeholder="CVE-2026-1234, …" /></div>
      <div><label className="label" htmlFor="mi-title">Title</label><input id="mi-title" name="title" className="input w-full" /></div>
      <div className="md:col-span-2"><label className="label" htmlFor="mi-sum">Summary</label><textarea id="mi-sum" name="summary" rows={2} className="input w-full" /></div>
      <div className="md:col-span-2"><label className="label" htmlFor="mi-desc">Details</label><textarea id="mi-desc" name="description" rows={3} className="input w-full" /></div>
      <div><label className="label" htmlFor="mi-sev">Severity</label><select id="mi-sev" name="severity" className="input w-full"><option value="">—</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s}>{s}</option>)}</select></div>
      <div><label className="label" htmlFor="mi-exp">Exploited</label><select id="mi-exp" name="exploited" className="input w-full"><option value="">Unknown</option><option value="yes">Yes</option><option value="no">No</option></select></div>
      <div><label className="label" htmlFor="mi-tlp">TLP</label><select id="mi-tlp" name="tlp" className="input w-full"><option value="">Source default</option>{["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"].map((t) => <option key={t}>{t}</option>)}</select></div>
      <div><label className="label" htmlFor="mi-url">Source URL</label><input id="mi-url" name="url" type="url" className="input w-full" /></div>
      <div><label className="label" htmlFor="mi-tags">Tags</label><input id="mi-tags" name="tags" className="input w-full" placeholder="ransomware, edge device" /></div>
      <div><label className="label" htmlFor="mi-att">Attachments (PDF / HTML)</label><input id="mi-att" type="file" multiple accept=".pdf,.html,.htm" className="text-sm" onChange={(e) => setFiles(e.target.files)} /></div>
      <div className="md:col-span-2"><label className="label" htmlFor="mi-notes">Analyst notes</label><textarea id="mi-notes" name="notes" rows={2} className="input w-full" /></div>
      <div className="md:col-span-2"><ErrorNote error={err} /><button className="btn-primary" disabled={busy}>{busy ? "Saving…" : "Add intel item"}</button>
        <span className="ml-2 text-xs text-ec-slate">Shown everywhere as “Manual — &lt;subscription&gt;”. TLP:RED stays inside the platform (no email, no AI).</span></div>
    </form>
  );
}

interface ImportPreview { format: string; valid: number; error_count: number; errors: { row: number; error: string }[]; sample: Record<string, unknown>[] }

export function IntelImport() {
  const qc = useQueryClient();
  const sources = useSources();
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const run = async (form: HTMLFormElement, commit: boolean) => {
    setErr(null); setResult(null);
    const fd = new FormData(form);
    try {
      if (!commit) setPreview(await upload<ImportPreview>("/api/subscriptions/import/preview", fd));
      else {
        fd.set("skip_invalid", "true");
        const r = await upload<{ imported: number; skipped_invalid: number }>("/api/subscriptions/import", fd);
        setResult(`Imported ${r.imported} item(s); skipped ${r.skipped_invalid} invalid row(s).`); setPreview(null); form.reset();
        qc.invalidateQueries({ queryKey: ["intel"] });
      }
    } catch (x) { setErr(x); }
  };
  return (
    <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); run(e.currentTarget, false); }}>
      <p className="text-sm text-ec-slate">CSV (columns: kind, cve_ids, title, summary, description, severity, exploited, url, published_at, tags, tlp, notes), a JSON list of the same fields, or a STIX 2.1 bundle (vulnerability and report objects).</p>
      <div className="flex flex-wrap items-end gap-2">
        <div><label className="label" htmlFor="im-sub">Source subscription</label><select id="im-sub" name="subscription_id" className="input" required>{sources.data?.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></div>
        <div><label className="label" htmlFor="im-file">File</label><input id="im-file" name="file" type="file" accept=".csv,.json" className="text-sm" required /></div>
        <button className="btn-secondary">Validate</button>
      </div>
      {preview && (
        <div className="rounded-sm border border-ec-border p-3 text-sm">
          <p><strong>{preview.valid}</strong> valid row(s), <strong>{preview.error_count}</strong> invalid ({preview.format}).</p>
          {preview.errors.length > 0 && <ul className="ml-5 list-disc text-xs text-red-800">{preview.errors.slice(0, 20).map((e) => <li key={e.row}>Row {e.row}: {e.error}</li>)}</ul>}
          {preview.sample.length > 0 && <ul className="ml-5 mt-1 list-disc text-xs">{preview.sample.map((s, n) => <li key={n}>{String(s.title)} {(s.cve_ids as string[]).join(", ")} · TLP:{String(s.tlp)}</li>)}</ul>}
          <button type="button" className="btn-primary mt-2" disabled={preview.valid === 0} onClick={(e) => run(e.currentTarget.form!, true)}>Import {preview.valid} valid row(s)</button>
        </div>
      )}
      {result && <p role="status" className="text-sm text-emerald-900">{result}</p>}
      <ErrorNote error={err} />
    </form>
  );
}

/** CVE detail panel: subscription intel for one CVE (+ quick manual entry for intel:manage). */
export function CveIntelPanel({ cveId }: { cveId: string }) {
  const on = useSubscriptionsOn();
  const { can } = useAuth();
  const [adding, setAdding] = useState(false);
  const q = useQuery({ queryKey: ["intel", "cve", cveId], enabled: on,
                       queryFn: () => api<IntelItem[]>("/api/subscriptions/intel", { query: { cve_id: cveId } }) });
  if (!on) return null;
  return (
    <section className="card">
      <div className="mb-2 flex items-center justify-between"><h2 className="font-semibold">Subscription intelligence</h2>
        {can("intel:manage") && <button className="text-xs underline" onClick={() => setAdding((v) => !v)}>{adding ? "Close" : "Add intel"}</button>}</div>
      {adding && <div className="mb-3 rounded-sm border border-ec-border p-3"><ManualIntelForm cveId={cveId} onDone={() => setAdding(false)} /></div>}
      <ErrorNote error={q.error} />
      <IntelList items={q.data} empty="No licensed or manual intel for this CVE." />
    </section>
  );
}

/** Security News section: subscription news / reports, manual entry and import. */
export function NewsIntelSection() {
  const on = useSubscriptionsOn();
  const { can } = useAuth();
  const [tab, setTab] = useState<"items" | "add" | "import">("items");
  const q = useQuery({ queryKey: ["intel", "news"], enabled: on,
                       queryFn: () => api<IntelItem[]>("/api/subscriptions/intel", { query: { kind: "news", limit: 50 } }) });
  if (!on) return null;
  return (
    <section className="card mt-6">
      <div className="mb-3 flex flex-wrap items-center gap-2"><h2 className="mr-auto font-heading font-bold">Subscription intelligence</h2>
        <button className={tab === "items" ? "btn-primary" : "btn-secondary"} onClick={() => setTab("items")}>Reports</button>
        {can("intel:manage") && <><button className={tab === "add" ? "btn-primary" : "btn-secondary"} onClick={() => setTab("add")}>Add manually</button>
          <button className={tab === "import" ? "btn-primary" : "btn-secondary"} onClick={() => setTab("import")}>Import</button></>}</div>
      {tab === "items" && <><ErrorNote error={q.error} /><IntelList items={q.data} empty="No subscription reports yet." /></>}
      {tab === "add" && <ManualIntelForm onDone={() => setTab("items")} />}
      {tab === "import" && <IntelImport />}
    </section>
  );
}
