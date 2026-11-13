import { EmptyState, PageHeader } from "../components/ui";

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
