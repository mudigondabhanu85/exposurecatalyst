import { Component, type ErrorInfo, type ReactNode } from "react";
import { Link } from "react-router-dom";

/** Branded loading / error screen. mark-light.svg is used at 64 px (brand minimum for the mark with nodes). */
export function StatusScreen({ code, title, message, action, fullPage = false }: {
  code?: string; title: string; message?: string; action?: ReactNode; fullPage?: boolean;
}) {
  return (
    <div className={`flex flex-col items-center justify-center px-4 text-center ${fullPage ? "min-h-screen bg-ec-surface" : "py-16"}`} role={code ? "alert" : "status"}>
      <img src="/brand/svg/mark-light.svg" alt="" aria-hidden="true" width={64} height={64} className="mb-4 h-16 w-16" />
      {code && <p className="font-heading text-sm font-bold uppercase tracking-widest text-ec-slate">{code}</p>}
      <h1 className="font-heading text-2xl font-bold text-ec-navy">{title}</h1>
      {message && <p className="mt-2 max-w-md text-sm text-ec-slate">{message}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export const LoadingScreen = ({ fullPage = false }: { fullPage?: boolean }) => (
  <StatusScreen title="Loading…" fullPage={fullPage} />
);

export const NotFound = () => (
  <StatusScreen code="404" title="Page not found" message="The page you requested does not exist or has moved."
                action={<Link className="btn-primary" to="/cves">Go to CVE Intelligence</Link>} />
);

export const Forbidden = ({ message }: { message?: string }) => (
  <StatusScreen code="403" title="Not permitted" message={message ?? "Your role does not grant access to this area. Ask an administrator if you need it."} />
);

/** 500 screen: catches render errors so users never see a blank page or a stack trace. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("ui_error", error.message, info.componentStack); }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <StatusScreen code="500" fullPage title="Something went wrong"
                    message="An unexpected error occurred. Reload the page; if it keeps happening, contact your administrator."
                    action={<button className="btn-primary" onClick={() => window.location.reload()}>Reload</button>} />
    );
  }
}
