import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { HelpButton, InfoTip } from "../help";

/**
 * Severity palette — deliberately NOT brand orange (orange is a brand accent only, see brand/README.md).
 * Each badge always shows its text label, and differs by hue, lightness and a left-edge marker so it does
 * not rely on colour alone. All pairs meet WCAG AA (≥ 4.5:1).
 */
const SEV: Record<string, string> = {
  CRITICAL: "bg-[#7A0F1C] text-white border-l-4 border-[#3D0007]",       // 11.0:1
  HIGH: "bg-[#C21D2F] text-white border-l-4 border-[#7A0F1C]",           // 5.9:1
  MEDIUM: "bg-[#FCE38A] text-[#5C4200] border-l-4 border-[#C9A200]",     // 7.8:1
  LOW: "bg-[#DCE9FB] text-[#14386B] border-l-4 border-[#5B8BD0]",        // 9.8:1
  NONE: "bg-ec-surface-alt text-ec-slate border-l-4 border-ec-border",
  UNKNOWN: "bg-ec-surface-alt text-ec-slate border-l-4 border-ec-border",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`inline-block rounded-sm px-2 py-0.5 text-xs font-bold tracking-wide ${SEV[severity] ?? SEV.UNKNOWN}`}>{severity}</span>;
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
  pending: "bg-slate-100 text-ec-slate",
  disabled: "bg-slate-100 text-ec-slate",
};

export function HealthBadge({ health, title }: { health: string; title?: string }) {
  return <span title={title} className={`rounded px-2 py-0.5 text-xs font-semibold capitalize ${HEALTH[health] ?? HEALTH.pending}`}>{health}</span>;
}

export function PageHeader({ title, helpId, subtitle, actions }: { title: string; helpId: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="font-heading text-2xl font-bold text-ec-navy">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-ec-slate">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2">{actions}<HelpButton id={helpId} /></div>
    </div>
  );
}

export function EmptyState({ title, why, fix }: { title: string; why: string; fix?: { label: string; to: string } }) {
  return (
    <div className="rounded-lg border border-dashed border-ec-border bg-white p-8 text-center">
      <p className="font-heading text-base font-bold text-ec-navy">{title}</p>
      <p className="mx-auto mt-1 max-w-xl text-sm text-ec-slate">{why}</p>
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
