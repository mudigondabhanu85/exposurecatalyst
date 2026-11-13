// Thin fetch wrapper: same-origin cookies, CSRF header on unsafe methods, typed errors.

export class ApiError extends Error {
  constructor(public status: number, public detail: unknown) {
    super(typeof detail === "string" ? detail : (detail as { message?: string })?.message ?? `HTTP ${status}`);
  }
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)(?:__Host-)?excat_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

type Query = Record<string, string | number | boolean | string[] | undefined | null>;

export function qs(query?: Query): string {
  if (!query) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => p.append(k, x));
    else p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export async function api<T>(path: string, opts: { method?: string; body?: unknown; query?: Query } = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken();
  const res = await fetch(path + qs(opts.query), {
    method,
    headers,
    credentials: "same-origin",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") ?? "";
  const data = ct.includes("json") ? await res.json() : await res.text();
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith("/api/auth/")) window.dispatchEvent(new Event("excat:unauthorized"));
    throw new ApiError(res.status, (data as { detail?: unknown })?.detail ?? data);
  }
  return data as T;
}

// ---- shared types ------------------------------------------------------------------------------
export interface Me {
  id: number; username: string; display_name: string | null; email: string | null;
  roles: string[]; permissions: string[]; mfa_enabled: boolean; mfa_verified: boolean;
  tour_completed: boolean; csrf_token: string;
}
export interface CveSummary {
  cve_id: string; title: string | null; severity: string; cvss_score: number | null; cvss_version: string | null;
  epss_score: number | null; epss_percentile: number | null; kev: boolean; kev_due_date: string | null;
  exploit_available: boolean; published_at: string | null; last_modified_at: string | null; vendors: string[];
}
export interface CvePage { items: CveSummary[]; total: number; page: number; page_size: number }
export interface CvssMetric { version: string; score: number | null; vector: string | null; severity: string; source: string | null; type: string | null }
export interface Product {
  vendor: string; product: string; cpe: string | null; version_start_including: string | null;
  version_start_excluding: string | null; version_end_including: string | null; version_end_excluding: string | null;
  vulnerable: boolean; source: string;
}
export interface CveEvent { event_type: string; occurred_at: string; source: string; detail: Record<string, unknown> }
export interface CveDetail extends CveSummary {
  description: string | null; vuln_status: string | null; cvss_vector: string | null; cvss_metrics: CvssMetric[];
  kev_date_added: string | null; kev_required_action: string | null; kev_ransomware_use: string | null;
  epss_date: string | null; cwes: string[]; references: { url: string; source: string | null; tags: string[] }[];
  exploit_refs: string[]; patch_refs: string[]; provenance: Record<string, { source: string; at: string }>;
  products: Product[]; events: CveEvent[];
}
export interface SourceInfo {
  source: string; label: string; enabled: boolean; status: string; health: string; interval_minutes: number;
  last_attempt_at: string | null; last_success_at: string | null; last_error: string | null;
  records_last_run: number; refresh_pending: boolean;
}
export interface SourcesResp { scheduler_alive: boolean; scheduler_heartbeat_at: string | null; sources: SourceInfo[] }
export interface SavedSearch { id: number; name: string; query: Record<string, unknown>; created_at: string }
export interface HelpTopic { id: string; title: string; summary: string; page: string | null; docs: string | null }
export interface HelpPage extends HelpTopic { markdown: string }
export type Tooltips = Record<string, { label: string; text: string }>;

export const fmtDate = (s: string | null | undefined) => (s ? s.slice(0, 10) : "—");
export const fmtDateTime = (s: string | null | undefined) => (s ? s.replace("T", " ").slice(0, 16) + " UTC" : "—");
export const pct = (n: number | null | undefined, digits = 1) => (n === null || n === undefined ? "—" : `${(n * 100).toFixed(digits)} %`);
