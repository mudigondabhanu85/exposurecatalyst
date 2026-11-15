import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";

interface Banner { id: string; level: "info" | "warning" | "error"; title: string; message: string; dismissible: boolean; link?: string }
const STYLE: Record<Banner["level"], string> = {
  info: "border-sky-300 bg-sky-50 text-sky-950",
  warning: "border-amber-400 bg-amber-50 text-amber-950",
  error: "border-red-400 bg-red-50 text-red-900",
};

/** Admin-only deployment banners (domain changed, self-signed / expiring certificate). Empty for everyone else. */
export function DeploymentBanners() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["system-banners"], queryFn: () => api<Banner[]>("/api/system/banners"), staleTime: 300_000 });
  const dismiss = useMutation({ mutationFn: (id: string) => api(`/api/system/banners/${id}/dismiss`, { method: "POST" }),
                                onSuccess: () => qc.invalidateQueries({ queryKey: ["system-banners"] }) });
  if (!q.data?.length) return null;
  return (
    <div className="mx-auto max-w-7xl space-y-2 px-4 pt-4">
      {q.data.map((b) => (
        <div key={b.id} role={b.level === "error" ? "alert" : "status"} className={`flex flex-wrap items-center gap-2 rounded-sm border px-3 py-2 text-sm ${STYLE[b.level]}`}>
          <strong>{b.title}.</strong><span className="flex-1">{b.message}</span>
          {b.link && <Link to={b.link} className="underline">Review</Link>}
          {b.dismissible && <button className="text-xs underline" onClick={() => dismiss.mutate(b.id)}>Dismiss</button>}
        </div>
      ))}
    </div>
  );
}
