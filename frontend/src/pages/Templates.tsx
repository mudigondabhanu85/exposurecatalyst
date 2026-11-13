import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fmtDateTime, type Template } from "../api";
import { useAuth } from "../auth";
import { ErrorNote, PageHeader } from "../components/ui";

const VSTYLE: Record<string, string> = { draft: "bg-ec-surface-alt", in_review: "bg-[#FFF4CC] text-[#5C4200]", approved: "bg-emerald-100 text-emerald-900", retired: "bg-ec-surface-alt text-ec-slate" };

export default function TemplatesPage() {
  const { can, me } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["templates"], queryFn: () => api<Template[]>("/api/templates") });
  const [editing, setEditing] = useState<number | null>(null);
  const done = (t: Template) => { qc.setQueryData<Template[]>(["templates"], (old) => old?.map((x) => (x.id === t.id ? t : x))); setEditing(null); };
  const act = useMutation({ mutationFn: ({ path, body }: { path: string; body?: unknown }) => api<Template>(path, { method: "POST", body }), onSuccess: done });

  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-sm"><Link className="link" to="/advisories">Advisories</Link> / Templates</nav>
      <PageHeader title="Advisory templates" helpId="advisory-templates" subtitle="Versioned · draft → review → approved · the branded layout, header and footer are fixed" />
      <ErrorNote error={act.error} />
      <div className="space-y-4">
        {q.data?.map((t) => {
          const latest = t.versions[t.versions.length - 1];
          return (
            <section key={t.id} className="card">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <div><h2 className="font-heading text-lg font-bold">{t.name}</h2><p className="text-sm text-ec-slate">{t.description}</p></div>
                {can("template:manage") && <button className="btn-secondary" onClick={() => setEditing(editing === t.id ? null : t.id)}>{editing === t.id ? "Close" : "New version"}</button>}
              </div>
              {editing === t.id && (
                <form className="mb-3 space-y-2" onSubmit={(e) => { e.preventDefault(); const fd = new FormData(e.currentTarget);
                  act.mutate({ path: `/api/templates/${t.id}/versions`, body: { subject_template: fd.get("s"), body_template: fd.get("b"), change_note: fd.get("n") || null } }); }}>
                  <label className="label" htmlFor={`s${t.id}`}>Subject template</label>
                  <input id={`s${t.id}`} name="s" className="input w-full font-mono text-xs" defaultValue={latest.subject_template} required />
                  <label className="label" htmlFor={`b${t.id}`}>Body template (Jinja, sandboxed)</label>
                  <textarea id={`b${t.id}`} name="b" rows={12} className="input w-full font-mono text-xs" defaultValue={latest.body_template} required />
                  <p className="text-xs text-ec-slate">Available: <code>advisory.*</code>, <code>cve.*</code>, <code>exposure.*</code>, <code>product</code>, and blocks <code>components.summary_table</code>, <code>components.validation_matrix</code>, <code>components.section(title, text)</code>. Use inline styles — email clients ignore stylesheets.</p>
                  <input name="n" className="input w-full" placeholder="Change note" maxLength={500} />
                  <button className="btn-primary">Save draft version</button>
                </form>
              )}
              <table className="min-w-full text-sm">
                <thead className="bg-ec-surface-alt"><tr><th className="th">Version</th><th className="th">Status</th><th className="th">Author</th><th className="th">Approved</th><th className="th">Note</th><th className="th" /></tr></thead>
                <tbody>{[...t.versions].reverse().map((v) => (
                  <tr key={v.id} className="border-t border-ec-surface-alt">
                    <td className="td">v{v.version}</td><td className="td"><span className={`rounded-sm px-2 py-0.5 text-xs font-semibold ${VSTYLE[v.status] ?? ""}`}>{v.status.replace("_", " ")}</span></td>
                    <td className="td">{v.created_by ?? "—"}</td><td className="td text-xs">{v.approved_by ? `${v.approved_by} · ${fmtDateTime(v.approved_at)}` : "—"}</td>
                    <td className="td text-xs">{v.change_note}</td>
                    <td className="td whitespace-nowrap">
                      {v.status === "draft" && can("template:manage") && <button className="btn-secondary" onClick={() => act.mutate({ path: `/api/template-versions/${v.id}/submit` })}>Submit</button>}
                      {v.status === "in_review" && can("advisory:approve") && v.created_by !== me?.username && <button className="btn-primary" onClick={() => act.mutate({ path: `/api/template-versions/${v.id}/approve` })}>Approve</button>}
                    </td>
                  </tr>))}
                </tbody>
              </table>
            </section>
          );
        })}
      </div>
    </>
  );
}
