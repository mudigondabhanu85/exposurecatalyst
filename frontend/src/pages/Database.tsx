import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { ErrorNote, PageHeader } from "../components/ui";

interface Engine { engine: string; recommended: boolean; extra: string | null; url: string; managed: string }
interface DbStatus {
  engine: string; driver: string; host: string | null; port: number | null; database: string | null; username: string | null;
  password_configured: boolean; tls_mode: string | null; tls: boolean | null; version: string | null; env: string; dev_only: boolean;
  connected: boolean; error: string | null;
  pool: { size: number; max_overflow: number; recycle_seconds: number; checked_out: number | null } | null;
  migrations?: { current: string[]; head: string[]; pending: { revision: string; message: string }[]; up_to_date: boolean };
  privileges?: { checked: boolean; role?: string; least_privilege: boolean | null; issues?: string[]; note: string | null };
  redis: { used: boolean; note: string };
  engines: Engine[];
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return <div className="flex gap-3 border-t border-ec-surface-alt py-1.5 text-sm first:border-t-0"><dt className="w-40 shrink-0 text-ec-slate">{k}</dt><dd className="break-all">{v ?? "—"}</dd></div>;
}

function Pill({ ok, children }: { ok: boolean | null | undefined; children: React.ReactNode }) {
  const cls = ok === null || ok === undefined ? "bg-ec-surface-alt text-ec-slate" : ok ? "bg-emerald-50 text-emerald-900" : "bg-amber-50 text-amber-900";
  return <span className={`rounded-sm px-2 py-0.5 text-xs font-semibold ${cls}`}>{children}</span>;
}

export default function DatabaseSettings() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["db-status"], queryFn: () => api<DbStatus>("/api/settings/database") });
  const test = useMutation({ mutationFn: () => api<{ ok: boolean; message: string; latency_ms: number }>("/api/settings/database/test", { method: "POST" }) });
  const migrate = useMutation({ mutationFn: () => api<{ message: string }>("/api/settings/database/migrate", { method: "POST" }),
                                onSuccess: () => qc.invalidateQueries({ queryKey: ["db-status"] }) });
  const d = q.data;
  return (
    <>
      <PageHeader title="Database" helpId="settings-database" subtitle="Connection, migrations and least-privilege status"
                  actions={<button className="btn-primary" disabled={test.isPending} onClick={() => test.mutate()}>{test.isPending ? "Testing…" : "Test connection"}</button>} />
      <ErrorNote error={q.error ?? test.error ?? migrate.error} />
      {test.data && <p role="status" className={`mb-3 rounded-sm px-3 py-2 text-sm ${test.data.ok ? "bg-emerald-50 text-emerald-900" : "bg-red-50 text-red-800"}`}>
        {test.data.ok ? `Connected · round trip ${test.data.latency_ms} ms` : test.data.message}</p>}
      {d && (
        <div className="space-y-4">
          {d.dev_only && <p role="alert" className="rounded-sm border border-amber-400 bg-amber-50 px-3 py-2 text-sm text-amber-900">
            SQLite is for development only. Use PostgreSQL (recommended) for anything shared; production refuses to start on SQLite.</p>}
          <section className="card">
            <h2 className="mb-2 flex items-center gap-2 font-heading font-bold">Connection <Pill ok={d.connected}>{d.connected ? "Connected" : "Unreachable"}</Pill></h2>
            {d.error && <p className="mb-2 text-sm text-red-800">{d.error}</p>}
            <dl>
              <Row k="Engine" v={<>{d.engine} <span className="text-ec-slate">({d.driver}{d.version ? ` · server ${d.version}` : ""})</span></>} />
              <Row k="Host / port" v={d.host ? `${d.host}${d.port ? `:${d.port}` : ""}` : null} />
              <Row k="Database" v={d.database} />
              <Row k="User" v={d.username} />
              <Row k="Password" v={d.password_configured ? "Configured (never shown)" : d.engine === "sqlite" ? "Not applicable" : "Not set"} />
              <Row k="TLS" v={d.engine === "sqlite" ? "Not applicable" : <>{d.tls === true ? <Pill ok>In use</Pill> : d.tls === false ? <Pill ok={false}>Not in use</Pill> : null}{d.tls_mode && <span className="ml-2 text-ec-slate">mode {d.tls_mode}</span>}</>} />
              {d.pool && <Row k="Pool" v={`${d.pool.size} connections + ${d.pool.max_overflow} overflow · recycle ${d.pool.recycle_seconds}s · ${d.pool.checked_out ?? 0} in use`} />}
            </dl>
            <p className="mt-3 text-xs text-ec-slate">The connection comes from deployment configuration (<code>EXCAT_DATABASE_URL</code>, <code>EXCAT_DATABASE_PASSWORD</code> from your secret store) and is read-only here, so database credentials are never stored in the application or changeable from a browser. Pool size: <code>EXCAT_DB_POOL_SIZE</code>, <code>EXCAT_DB_MAX_OVERFLOW</code>, <code>EXCAT_DB_POOL_RECYCLE_SECONDS</code>.</p>
          </section>

          {d.migrations && (
            <section className="card">
              <h2 className="mb-2 flex items-center gap-2 font-heading font-bold">Schema migrations <Pill ok={d.migrations.up_to_date}>{d.migrations.up_to_date ? "Up to date" : `${d.migrations.pending.length} pending`}</Pill></h2>
              <dl><Row k="Current revision" v={d.migrations.current.join(", ") || "none (empty database)"} /><Row k="Latest revision" v={d.migrations.head.join(", ")} /></dl>
              {d.migrations.pending.length > 0 && (
                <>
                  <ul className="my-2 ml-5 list-disc text-sm">{d.migrations.pending.map((m) => <li key={m.revision}><code>{m.revision}</code> {m.message}</li>)}</ul>
                  <button className="btn-secondary" disabled={migrate.isPending} onClick={() => migrate.mutate()}>{migrate.isPending ? "Applying…" : "Apply pending migrations"}</button>
                  <p className="mt-2 text-xs text-ec-slate">Production: run the migration task instead (<code>exposurecatalyst migrate --app-role excat_app</code> as the database owner). Take a snapshot first.</p>
                </>
              )}
              {migrate.data && <p role="status" className="mt-2 text-sm">{migrate.data.message}</p>}
            </section>
          )}

          {d.privileges && (
            <section className="card">
              <h2 className="mb-2 flex items-center gap-2 font-heading font-bold">Least privilege <Pill ok={d.privileges.least_privilege}>{d.privileges.least_privilege === null ? "Not checked" : d.privileges.least_privilege ? "DML-only role" : "Over-privileged"}</Pill></h2>
              {d.privileges.checked ? (
                <>
                  <p className="text-sm">The app is connected as <code>{d.privileges.role}</code>.</p>
                  {d.privileges.issues && d.privileges.issues.length > 0
                    ? <ul className="my-2 ml-5 list-disc text-sm text-amber-900">{d.privileges.issues.map((i) => <li key={i}>{i}</li>)}</ul>
                    : <p className="text-sm text-ec-slate">It can read and write data but cannot change the schema or rewrite the audit log.</p>}
                </>
              ) : null}
              {d.privileges.note && <p className="mt-1 text-xs text-ec-slate">{d.privileges.note}</p>}
            </section>
          )}

          <section className="card">
            <h2 className="mb-2 font-heading font-bold">Supported engines</h2>
            <div className="overflow-x-auto"><table className="min-w-full text-sm">
              <thead className="bg-ec-surface-alt"><tr><th className="th">Engine</th><th className="th">EXCAT_DATABASE_URL format</th><th className="th">Install extra</th><th className="th">Managed services</th></tr></thead>
              <tbody>{d.engines.map((e) => (
                <tr key={e.engine} className="border-t border-ec-surface-alt">
                  <td className="td font-medium">{e.engine}{e.recommended && <span className="ml-1"><Pill ok>Recommended</Pill></span>}{e.engine.startsWith(d.engine === "postgresql" ? "PostgreSQL" : d.engine === "sqlite" ? "SQLite" : "—") && <span className="ml-1 text-xs text-ec-slate">(in use)</span>}</td>
                  <td className="td"><code className="text-xs">{e.url}</code></td>
                  <td className="td">{e.extra ? <code className="text-xs">pip install "exposurecatalyst[{e.extra}]"</code> : "built in"}</td>
                  <td className="td text-xs text-ec-slate">{e.managed}</td>
                </tr>))}</tbody>
            </table></div>
          </section>

          <section className="card">
            <h2 className="mb-1 font-heading font-bold">Redis (optional)</h2>
            <p className="text-sm text-ec-slate">{d.redis.note}</p>
          </section>
        </div>
      )}
    </>
  );
}
