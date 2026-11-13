import { createContext, useContext, useEffect, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Me } from "./api";

interface AuthCtx {
  me: Me | null;
  loading: boolean;
  can: (perm: string) => boolean;
  refresh: () => void;
}

const Ctx = createContext<AuthCtx>({ me: null, loading: true, can: () => false, refresh: () => {} });

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const q = useQuery<Me | null>({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        return await api<Me>("/api/auth/me");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    staleTime: 60_000,
  });
  useEffect(() => {
    const onUnauthorized = () => qc.setQueryData(["me"], null);
    window.addEventListener("excat:unauthorized", onUnauthorized);
    return () => window.removeEventListener("excat:unauthorized", onUnauthorized);
  }, [qc]);
  const me = q.data ?? null;
  // UI gating is a convenience only — the API enforces every permission server-side.
  const can = (perm: string) => !!me?.permissions.includes(perm);
  return (
    <Ctx.Provider value={{ me, loading: q.isLoading, can, refresh: () => qc.invalidateQueries({ queryKey: ["me"] }) }}>
      {children}
    </Ctx.Provider>
  );
}

export const useAuth = () => useContext(Ctx);
