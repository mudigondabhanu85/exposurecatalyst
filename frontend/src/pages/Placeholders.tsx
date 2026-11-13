import { Link, useSearchParams } from "react-router-dom";
import { EmptyState, PageHeader } from "../components/ui";

export function AdvisoriesPage() {
  const [params] = useSearchParams();
  const cve = params.get("cve");
  return (
    <>
      <PageHeader title="Advisory Email Generator" helpId="advisories" subtitle="Build, review and send stakeholder advisories" />
      {cve && (
        <p className="card mb-4 text-sm">
          Pre-selected CVE: <Link className="font-mono link" to={`/cves/${encodeURIComponent(cve)}`}>{cve}</Link>
        </p>
      )}
      <EmptyState title="Advisory generator arrives in Phase 2"
                  why="Templates, the asset validation matrix, Excel attachments, .eml / Copy-for-Outlook / SMTP delivery and the approval workflow ship in the next phase."
                  fix={{ label: "Back to CVE Intelligence", to: "/cves" }} />
    </>
  );
}

export function NewsPage() {
  return (
    <>
      <PageHeader title="Security News" helpId="news" subtitle="Trusted security news, de-duplicated and linked to CVEs" />
      <EmptyState title="Security News arrives in Phase 5"
                  why="RSS/API ingestion from CISA, BleepingComputer, The Hacker News, vendor threat-intel blogs and more, with CVE extraction and de-duplication."
                  fix={{ label: "Back to CVE Intelligence", to: "/cves" }} />
    </>
  );
}
