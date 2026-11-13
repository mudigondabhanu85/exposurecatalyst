import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { HelpButton, InfoTip } from "../help";

const SEV: Record<string, string> = {
  CRITICAL: "bg-red-700 text-white",
  HIGH: "bg-orange-600 text-white",
  MEDIUM: "bg-amber-300 text-amber-950",
  LOW: "bg-sky-200 text-sky-950",
  NONE: "bg-slate-200 text-slate-700",
  UNKNOWN: "bg-slate-200 text-slate-700",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`inline-block rounded px-2 py-0.5 text-xs font-bold ${SEV[severity] ?? SEV.UNKNOWN}`}>{severity}</span>;
}

export function KevBadge({ due }: { due?: string | null }) {
  return (
    <span className="inline-flex items-center gap-1 rounded bg-red-50 px-2 py-0.5 text-xs font-semibold text-red-800 ring-1 ring-red-200">
      KEV{due ? ` · due ${due}` : ""}
    </span>
  );
}

const HEALTH: Record<string, string> = {
  healthy: "bg-emerald-100 text-emerald-900",
  degraded: "bg-amber-100 text-amber-900",
  failing: "bg-red-100 text-red-900",
  pending: "bg-slate-100 text-slate-700",
  disabled: "bg-slate-100 text-slate-500",
};

export function HealthBadge({ health, title }: { health: string; title?: string }) {
  return <span title={title} className={`rounded px-2 py-0.5 text-xs font-semibold capitalize ${HEALTH[health] ?? HEALTH.pending}`}>{health}</span>;
}

export function PageHeader({ title, helpId, subtitle, actions }: { title: string; helpId: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold text-slate-900">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-slate-600">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2">{actions}<HelpButton id={helpId} /></div>
    </div>
  );
}

export function EmptyState({ title, why, fix }: { title: string; why: string; fix?: { label: string; to: string } }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-white p-8 text-center">
      <p className="text-base font-semibold text-slate-800">{title}</p>
      <p className="mx-auto mt-1 max-w-xl text-sm text-slate-600">{why}</p>
      {fix && <Link className="btn-primary mt-4" to={fix.to}>{fix.label}</Link>}
    </div>
  );
}

export function Field({ label, tip, htmlFor, children }: { label: string; tip?: string; htmlFor?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col">
      <label className="label" htmlFor={htmlFor}>{label}{tip && <InfoTip k={tip} />}</label>
      {children}
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  return <p role="alert" className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-800">{(error as Error).message}</p>;
}
