import Link from "next/link";
import {
  Activity,
  ArrowRight,
  Database,
  Fingerprint,
  Globe,
  Lock,
  Network,
  Server,
  Shield,
  ShieldAlert,
  Target,
} from "lucide-react";

const workflow = [
  {
    step: "01",
    title: "Create a case",
    description:
      "Define the scope, severity, and description of an investigation.",
    icon: Shield,
  },
  {
    step: "02",
    title: "Upload evidence",
    description:
      "Attach PCAP or PCAPNG files. The backend computes a SHA-256 hash on receipt for integrity tracking.",
    icon: Database,
  },
  {
    step: "03",
    title: "Analyze traffic",
    description:
      "Extract hosts, flows, DNS queries, HTTP transactions, and TLS handshakes from the capture.",
    icon: Network,
  },
  {
    step: "04",
    title: "Detect and correlate",
    description:
      "Run configured detection rules, extract indicators of compromise, and build a chronological timeline.",
    icon: ShieldAlert,
  },
  {
    step: "05",
    title: "Map to ATT&CK",
    description:
      "Correlate detections to MITRE ATT&CK techniques as investigative leads — not proof of attribution.",
    icon: Target,
  },
  {
    step: "06",
    title: "Produce a report",
    description:
      "Export a structured forensic report containing evidence metadata, findings, timeline, and provenance.",
    icon: Activity,
  },
];

const capabilities = [
  {
    icon: Server,
    title: "Host discovery",
    description:
      "Hosts observed in the capture, with bytes and packets sent and received, and unique peer counts.",
  },
  {
    icon: Network,
    title: "Network flows",
    description:
      "Aggregated source-to-destination conversations with protocol, ports, packet and byte totals, and time bounds.",
  },
  {
    icon: Globe,
    title: "DNS / HTTP / TLS",
    description:
      "Query names and answers, HTTP requests and responses, and TLS handshake metadata such as SNI and cipher.",
  },
  {
    icon: Fingerprint,
    title: "Indicators of compromise",
    description:
      "IPs, domains, URLs, and file hashes extracted from the evidence, with occurrence counts and confidence.",
  },
  {
    icon: Lock,
    title: "Evidence integrity",
    description:
      "SHA-256 hashes stored with each evidence file for chain-of-custody tracking.",
  },
  {
    icon: Target,
    title: "MITRE ATT&CK",
    description:
      "Technique mappings produced by the backend as investigative leads, with explicit confidence values.",
  },
];

export const metadata = {
  title: "About",
};

export default function AboutPage() {
  return (
    <div className="mx-auto w-full max-w-[1200px] p-5 md:p-7">
      {/* Hero */}
      <section className="mb-10">
        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-edge bg-surface-raised/70 px-3 py-1 text-[11px] font-medium text-content-muted backdrop-blur">
          <span className="size-1.5 rounded-full bg-accent" />
          About NetForensicX
        </div>

        <h1 className="text-3xl font-semibold tracking-tight text-content md:text-4xl">
          An evidence-driven network forensic workspace.
        </h1>

        <p className="mt-3 max-w-3xl text-sm leading-7 text-content-muted">
          NetForensicX is a platform for investigating packet capture evidence.
          It ingests PCAP files, extracts the observable facts of network
          traffic, and organizes them so an analyst can move from raw packets
          to a defensible investigation report without losing provenance along
          the way.
        </p>
      </section>

      {/* Workflow */}
      <section className="mb-10">
        <h2 className="text-lg font-semibold text-content">
          The investigative workflow
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-content-muted">
          Every step is backed by the existing backend services. Nothing here
          is simulated.
        </p>

        <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {workflow.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.step}
                className="group relative overflow-hidden rounded-2xl border border-edge bg-surface-raised/60 p-5 backdrop-blur-md transition hover:-translate-y-[1px] hover:border-accent/40"
              >
                <div className="flex items-center justify-between">
                  <div className="flex size-10 items-center justify-center rounded-xl bg-accent/10 text-accent">
                    <Icon className="size-5" />
                  </div>
                  <span className="font-mono text-[10px] tracking-wider text-content-subtle">
                    {item.step}
                  </span>
                </div>

                <h3 className="mt-4 text-sm font-semibold text-content">
                  {item.title}
                </h3>
                <p className="mt-2 text-xs leading-5 text-content-muted">
                  {item.description}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Capabilities */}
      <section className="mb-10">
        <h2 className="text-lg font-semibold text-content">
          What the platform extracts
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-content-muted">
          All findings come from the PCAP itself. The platform does not claim
          that an indicator is malicious solely because it appears in the
          capture.
        </p>

        <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {capabilities.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.title}
                className="rounded-2xl border border-edge bg-surface-raised/60 p-5 backdrop-blur-md"
              >
                <div className="flex size-10 items-center justify-center rounded-xl bg-accent/10 text-accent">
                  <Icon className="size-5" />
                </div>
                <h3 className="mt-4 text-sm font-semibold text-content">
                  {item.title}
                </h3>
                <p className="mt-2 text-xs leading-5 text-content-muted">
                  {item.description}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      {/* CTA */}
      <section className="rounded-2xl border border-edge bg-surface-raised/60 p-6 backdrop-blur-md">
        <div className="flex flex-col items-start justify-between gap-4 md:flex-row md:items-center">
          <div>
            <h2 className="text-base font-semibold text-content">
              Ready to investigate?
            </h2>
            <p className="mt-1 text-sm text-content-muted">
              Start from the Overview tab to create a case, or open an
              existing one from Cases.
            </p>
          </div>

          <div className="flex gap-2">
            <Link
              href="/"
              className="inline-flex h-10 items-center gap-2 rounded-lg border border-edge bg-surface-subtle px-4 text-sm font-medium text-content-muted transition hover:border-edge-strong hover:text-content"
            >
              Overview
              <ArrowRight className="size-4" />
            </Link>
            <Link
              href="/cases"
              className="inline-flex h-10 items-center gap-2 rounded-lg bg-accent px-4 text-sm font-semibold text-accent-foreground transition hover:bg-accent-muted"
            >
              Open cases
              <ArrowRight className="size-4" />
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}