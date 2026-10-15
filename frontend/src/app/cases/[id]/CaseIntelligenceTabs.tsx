"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Activity,
  Search,
  ShieldAlert,
  Fingerprint,
  Clock3,
  Target,
  ChevronDown,
  Network,
  CheckCircle2,
  Filter,
  ArrowUpRight,
  FileSearch,
  RefreshCw,
  Loader2,
  Play,
  CircleDot,
} from "lucide-react";

import {
  analyzeDetections,
  getDetections,
  getDetectionSummary,
  analyzeIOCs,
  getIOCs,
  buildTimeline,
  getTimeline,
  analyzeMitre,
  getMitreMappings,
  type Detection as ApiDetection,
  type DetectionSummary,
  type IOC as ApiIOC,
  type TimelineEvent as ApiTimelineEvent,
  type MitreMapping,
} from "@/lib/api";

import {
  EmptyState as SharedEmptyState,
  SeverityBadge,
  StatusBadge,
  formatTimestamp as sharedFormatTimestamp,
  humanize as sharedHumanize,
} from "@/components/nfx/primitives";

type TabId = "detections" | "iocs" | "timeline" | "mitre";

type Props = {
  caseId: string;
  evidenceId: string;
};

const tabItems = [
  {
    id: "detections" as const,
    label: "Threat Detection",
    description: "Review alerts and suspicious activity",
    icon: ShieldAlert,
  },
  {
    id: "iocs" as const,
    label: "IOC Analysis",
    description: "Investigate indicators of compromise",
    icon: Fingerprint,
  },
  {
    id: "timeline" as const,
    label: "Event Timeline",
    description: "Explore events chronologically",
    icon: Clock3,
  },
  {
    id: "mitre" as const,
    label: "MITRE ATT&CK",
    description: "Map activity to adversary techniques",
    icon: Target,
  },
];

function humanize(value: string | null | undefined): string {
  return sharedHumanize(value);
}

function formatTimestamp(value: number | string | null | undefined): string {
  return sharedFormatTimestamp(value);
}

function formatIOCType(value: string): string {
  const normalized = value.toLowerCase().replace(/[_\s-]+/g, "");

  if (normalized.includes("ip")) return "IP Address";
  if (normalized.includes("domain")) return "Domain";
  if (normalized.includes("url")) return "URL";
  if (normalized.includes("hash") || normalized.includes("md5") || normalized.includes("sha")) {
    return "File Hash";
  }
  if (normalized.includes("email")) return "Email";
  return humanize(value);
}

function MetricCardLocal({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: number | string;
  icon: typeof Activity;
}) {
  return (
    <div className="rounded-lg border border-edge bg-surface-subtle/60 p-4 transition hover:border-edge-strong">
      <Icon className="h-4 w-4 text-content-subtle" />
      <p className="mt-3 text-2xl font-semibold tabular-nums text-content">
        {value}
      </p>
      <p className="mt-1 text-xs text-content-subtle">{label}</p>
    </div>
  );
}

function Panel({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`overflow-hidden rounded-2xl border border-edge nfx-glass shadow-panel ${className}`}
    >
      {children}
    </section>
  );
}

export default function CaseIntelligenceTabs({ caseId, evidenceId }: Props) {
  const [activeTab, setActiveTab] = useState<TabId>("detections");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");

  const [detections, setDetections] = useState<ApiDetection[]>([]);
  const [summary, setSummary] = useState<DetectionSummary>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  });
  const [iocs, setIOCs] = useState<ApiIOC[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<ApiTimelineEvent[]>([]);
  const [mappings, setMappings] = useState<MitreMapping[]>([]);

  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    setNotice("");

    const results = await Promise.allSettled([
      getDetections(caseId, evidenceId, { limit: 500 }),
      getDetectionSummary(caseId, evidenceId),
      getIOCs(caseId, evidenceId, { limit: 500 }),
      getTimeline(caseId, evidenceId, { limit: 1000 }),
      getMitreMappings(caseId, evidenceId, { limit: 500 }),
    ]);

    const errors: string[] = [];

    if (results[0].status === "fulfilled") setDetections(results[0].value);
    else errors.push("detections");

    if (results[1].status === "fulfilled") setSummary(results[1].value);
    else errors.push("detection summary");

    if (results[2].status === "fulfilled") setIOCs(results[2].value);
    else errors.push("IOCs");

    if (results[3].status === "fulfilled") setTimelineEvents(results[3].value);
    else errors.push("timeline");

    if (results[4].status === "fulfilled") setMappings(results[4].value);
    else errors.push("MITRE mappings");

    if (errors.length > 0) {
      setError(
        `Could not load ${errors.join(", ")}. Check that the backend is running and the selected evidence is valid.`,
      );
    }

    setLoading(false);
  }, [caseId, evidenceId]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const runAction = useCallback(async () => {
    setBusyAction(true);
    setError("");
    setNotice("");

    try {
      if (activeTab === "detections") {
        const result = await analyzeDetections(caseId, evidenceId);
        setNotice(
          `Detection analysis complete: ${result.created} created, ${result.existing} already existed, ${result.total} total.`,
        );
      } else if (activeTab === "iocs") {
        const result = await analyzeIOCs(caseId, evidenceId);
        setNotice(
          `IOC extraction complete: ${result.created} created, ${result.updated} updated, ${result.total} total.`,
        );
      } else if (activeTab === "timeline") {
        const result = await buildTimeline(caseId, evidenceId);
        setNotice(
          `Timeline build complete: ${result.created} created, ${result.total} total.`,
        );
      } else {
        const result = await analyzeMitre(caseId, evidenceId);
        setNotice(
          `MITRE mapping complete: ${result.created} created, ${result.total} total mappings.`,
        );
      }

      await loadData();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "The analysis action failed.",
      );
    } finally {
      setBusyAction(false);
    }
  }, [activeTab, caseId, evidenceId, loadData]);

  const filteredDetections = useMemo(() => {
    const query = search.toLowerCase().trim();

    return detections.filter((item) => {
      const matchesSearch =
        !query ||
        [
          item.title,
          item.description,
          item.detection_type,
          item.source_ip ?? "",
          item.destination_ip ?? "",
          item.id,
        ]
          .join(" ")
          .toLowerCase()
          .includes(query);

      const matchesSeverity =
        severity === "All" ||
        item.severity.toLowerCase() === severity.toLowerCase();

      return matchesSearch && matchesSeverity;
    });
  }, [detections, search, severity]);

  const filteredIOCs = useMemo(() => {
    const query = search.toLowerCase().trim();

    return iocs.filter((item) =>
      [item.value, item.ioc_type, item.source, item.severity]
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [iocs, search]);

  const filteredTimeline = useMemo(() => {
    const query = search.toLowerCase().trim();

    return timelineEvents.filter((item) =>
      [
        item.title,
        item.description,
        item.event_type,
        item.source_ip ?? "",
        item.destination_ip ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [timelineEvents, search]);

  const filteredMappings = useMemo(() => {
    const query = search.toLowerCase().trim();

    return mappings.filter((item) =>
      [item.technique_id, item.technique_name, item.tactic, item.description]
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [mappings, search]);

  const [selectedMappingId, setSelectedMappingId] = useState("");

  const selectedMapping =
    filteredMappings.find((item) => item.id === selectedMappingId) ??
    filteredMappings[0] ??
    null;

  const activeTitle = tabItems.find((tab) => tab.id === activeTab) ?? tabItems[0];

  const actionLabels: Record<TabId, string> = {
    detections: "Run detection analysis",
    iocs: "Extract IOCs",
    timeline: "Build timeline",
    mitre: "Map MITRE techniques",
  };

  const actionDescriptions: Record<TabId, string> = {
    detections: "Run the configured detection rules against this evidence.",
    iocs: "Extract indicators from the evidence using the backend analyzer.",
    timeline: "Build chronological events from available evidence and detections.",
    mitre: "Map available detections to supported MITRE ATT&CK techniques.",
  };

  return (
    <div className="min-w-0 space-y-6 text-content">
      {/* Header */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.18em] text-accent">
            <Network className="h-4 w-4" />
            Network forensics
          </div>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight text-content">
            Security Intelligence
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-content-muted">
            Investigate detections, examine indicators, reconstruct events,
            and map suspicious activity to MITRE ATT&CK.
          </p>
          <p className="mt-2 break-all font-mono text-xs text-content-subtle">
            Evidence: {evidenceId}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-2 rounded-lg border border-edge bg-surface-subtle px-3 py-2 text-xs text-content-muted">
            <CircleDot
              className={`h-3.5 w-3.5 ${
                loading ? "text-severity-medium" : "text-status-verified"
              }`}
            />
            {loading ? "Loading evidence" : "Data request complete"}
          </div>
          <button
            type="button"
            onClick={() => void loadData()}
            disabled={loading || busyAction}
            className="inline-flex h-9 items-center gap-2 rounded-lg border border-edge bg-surface-subtle px-3 text-xs font-medium text-content-muted transition hover:border-edge-strong hover:text-content disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Tab cards — visible active state, clearly clickable */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {tabItems.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;

          const count =
            tab.id === "detections"
              ? detections.length
              : tab.id === "iocs"
                ? iocs.length
                : tab.id === "timeline"
                  ? timelineEvents.length
                  : mappings.length;

          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => {
                setActiveTab(tab.id);
                setSearch("");
                setSeverity("All");
                setError("");
                setNotice("");
              }}
              aria-pressed={isActive}
              className={[
                "group relative overflow-hidden rounded-xl border p-4 text-left transition-all duration-200",
                isActive
                  ? "border-accent/60 bg-accent/[0.08] shadow-[0_12px_36px_-16px_color-mix(in_oklab,var(--color-accent)_55%,transparent)]"
                  : "border-edge bg-surface-subtle/60 hover:-translate-y-[1px] hover:border-accent/30 hover:bg-surface-subtle",
              ].join(" ")}
            >
              {/* active left bar */}
              <span
                aria-hidden
                className={[
                  "absolute left-0 top-4 bottom-4 w-[3px] rounded-r-full transition-all",
                  isActive ? "bg-accent opacity-100" : "bg-accent opacity-0",
                ].join(" ")}
              />

              <div className="flex items-center justify-between">
                <div
                  className={[
                    "flex h-9 w-9 items-center justify-center rounded-lg transition",
                    isActive
                      ? "bg-accent/15 text-accent"
                      : "bg-surface-overlay text-content-muted group-hover:text-accent",
                  ].join(" ")}
                >
                  <Icon className="h-4 w-4" />
                </div>
                <span className="text-xs font-medium tabular-nums text-content-subtle">
                  {loading ? "…" : count}
                </span>
              </div>

              <h3 className="mt-4 text-sm font-semibold text-content">
                {tab.label}
              </h3>
              <p className="mt-1 text-xs leading-5 text-content-subtle">
                {tab.description}
              </p>

              <div
                className={[
                  "mt-4 h-0.5 rounded-full transition-all",
                  isActive
                    ? "w-full bg-accent"
                    : "w-8 bg-edge group-hover:w-14 group-hover:bg-accent/50",
                ].join(" ")}
              />

              {isActive && (
                <span className="absolute right-3 top-3 rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-accent">
                  Active
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Alert */}
      {(error || notice) && (
        <div
          role={error ? "alert" : "status"}
          className={[
            "rounded-lg border p-4 text-sm",
            error
              ? "border-severity-critical/30 bg-severity-critical/10 text-severity-critical"
              : "border-status-verified/30 bg-status-verified/10 text-status-verified",
          ].join(" ")}
        >
          <div className="flex items-start gap-2">
            {error ? (
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            ) : (
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
            )}
            <p>{error || notice}</p>
          </div>
        </div>
      )}

      <Panel>
        {/* Panel toolbar */}
        <div className="flex flex-col justify-between gap-4 border-b border-edge p-5 sm:flex-row sm:items-center">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/10 text-accent">
              <activeTitle.icon className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-semibold text-content">{activeTitle.label}</h3>
              <p className="mt-1 text-xs text-content-subtle">
                {activeTitle.description}
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-2 sm:flex-row">
            <label className="relative block">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-content-subtle" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search records…"
                className="h-9 w-full rounded-lg border border-edge bg-surface-subtle pl-9 pr-3 text-sm text-content outline-none placeholder:text-content-subtle focus:border-accent sm:w-56"
              />
            </label>

            {activeTab === "detections" && (
              <label className="relative flex h-9 items-center rounded-lg border border-edge bg-surface-subtle px-2">
                <Filter className="mr-2 h-3.5 w-3.5 text-content-subtle" />
                <select
                  value={severity}
                  onChange={(event) => setSeverity(event.target.value)}
                  className="max-w-32 bg-transparent text-xs text-content outline-none"
                  aria-label="Filter by severity"
                >
                  {["All", "Critical", "High", "Medium", "Low", "Info"].map(
                    (item) => (
                      <option key={item} value={item}>
                        {item === "All" ? "All severity" : item}
                      </option>
                    ),
                  )}
                </select>
                <ChevronDown className="ml-1 h-3 w-3 text-content-subtle" />
              </label>
            )}

            <button
              type="button"
              onClick={() => void runAction()}
              disabled={loading || busyAction}
              title={actionDescriptions[activeTab]}
              className="inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-lg bg-accent px-3 text-xs font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busyAction ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Play className="h-3.5 w-3.5" />
              )}
              {busyAction ? "Analyzing…" : actionLabels[activeTab]}
            </button>
          </div>
        </div>

        {loading ? (
          <div className="flex min-h-64 items-center justify-center gap-3 text-sm text-content-muted">
            <Loader2 className="h-5 w-5 animate-spin text-accent" />
            Loading security intelligence for this evidence…
          </div>
        ) : (
          <>
            {activeTab === "detections" && (
              <>
                <div className="grid grid-cols-2 gap-3 border-b border-edge p-5 lg:grid-cols-4">
                  <MetricCardLocal label="Total detections" value={summary.total} icon={Activity} />
                  <MetricCardLocal label="Critical findings" value={summary.critical} icon={AlertTriangle} />
                  <MetricCardLocal label="High severity" value={summary.high} icon={ShieldAlert} />
                  <MetricCardLocal
                    label="Under investigation"
                    value={detections.filter((d) => d.status.toLowerCase() === "investigating").length}
                    icon={Search}
                  />
                </div>

                {filteredDetections.length === 0 ? (
                  <SharedEmptyState
                    title={search || severity !== "All" ? "No matching detections" : "No detections found"}
                    description={
                      search || severity !== "All"
                        ? "Change your search or severity filter."
                        : "No detection records currently exist for this evidence. Use Run detection analysis to execute the configured backend rules."
                    }
                  />
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[800px] text-left text-sm">
                      <thead className="border-b border-edge bg-surface-overlay/40 text-[10px] uppercase tracking-wider text-content-subtle">
                        <tr>
                          <th className="px-5 py-3 font-medium">Detection</th>
                          <th className="px-5 py-3 font-medium">Severity</th>
                          <th className="px-5 py-3 font-medium">Source / Destination</th>
                          <th className="px-5 py-3 font-medium">Time</th>
                          <th className="px-5 py-3 font-medium">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-edge">
                        {filteredDetections.map((item) => (
                          <tr key={item.id} className="transition hover:bg-surface-overlay/40">
                            <td className="px-5 py-4">
                              <p className="font-medium text-content">{item.title}</p>
                              <p className="mt-1 text-xs text-content-subtle">
                                {humanize(item.detection_type)} · {item.id}
                              </p>
                              <p className="mt-1 max-w-xl text-xs leading-5 text-content-subtle">
                                {item.description}
                              </p>
                            </td>
                            <td className="px-5 py-4">
                              <SeverityBadge value={item.severity} />
                            </td>
                            <td className="px-5 py-4 text-xs text-content-muted">
                              <p>{item.source_ip ?? "Unknown source"}</p>
                              <p className="mt-1">
                                → {item.destination_ip ?? "Unknown destination"}
                                {item.destination_port ? `:${item.destination_port}` : ""}
                              </p>
                            </td>
                            <td className="px-5 py-4 text-xs text-content-muted">
                              {formatTimestamp(item.timestamp)}
                            </td>
                            <td className="px-5 py-4">
                              <StatusBadge value={item.status} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {activeTab === "iocs" && (
              <>
                <div className="grid grid-cols-2 gap-3 border-b border-edge p-5 lg:grid-cols-4">
                  <MetricCardLocal label="Total indicators" value={iocs.length} icon={Fingerprint} />
                  <MetricCardLocal
                    label="IP addresses"
                    value={iocs.filter((x) => formatIOCType(x.ioc_type) === "IP Address").length}
                    icon={Network}
                  />
                  <MetricCardLocal
                    label="Domains"
                    value={iocs.filter((x) => formatIOCType(x.ioc_type) === "Domain").length}
                    icon={Search}
                  />
                  <MetricCardLocal
                    label="File hashes"
                    value={iocs.filter((x) => formatIOCType(x.ioc_type) === "File Hash").length}
                    icon={ShieldAlert}
                  />
                </div>

                {filteredIOCs.length === 0 ? (
                  <SharedEmptyState
                    title={search ? "No matching indicators" : "No IOC records found"}
                    description={
                      search
                        ? "Try another indicator value, type, source, or severity."
                        : "No indicators are stored for this evidence yet. Use Extract IOCs to run your existing IOC extraction service."
                    }
                  />
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[760px] text-left text-sm">
                      <thead className="border-b border-edge bg-surface-overlay/40 text-[10px] uppercase tracking-wider text-content-subtle">
                        <tr>
                          <th className="px-5 py-3 font-medium">Indicator</th>
                          <th className="px-5 py-3 font-medium">Type</th>
                          <th className="px-5 py-3 font-medium">Severity</th>
                          <th className="px-5 py-3 font-medium">Source</th>
                          <th className="px-5 py-3 font-medium">Occurrences</th>
                          <th className="px-5 py-3 font-medium">Confidence</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-edge">
                        {filteredIOCs.map((ioc) => (
                          <tr key={ioc.id} className="transition hover:bg-surface-overlay/40">
                            <td className="break-all px-5 py-4 font-mono text-xs text-accent">
                              {ioc.value}
                            </td>
                            <td className="px-5 py-4 text-content-muted">
                              {formatIOCType(ioc.ioc_type)}
                            </td>
                            <td className="px-5 py-4">
                              <SeverityBadge value={ioc.severity} />
                            </td>
                            <td className="px-5 py-4 text-xs text-content-muted">
                              {humanize(ioc.source)}
                            </td>
                            <td className="px-5 py-4 tabular-nums text-content-muted">
                              {ioc.occurrences}
                            </td>
                            <td className="px-5 py-4 text-content-muted">
                              {Math.round(
                                ioc.confidence <= 1
                                  ? ioc.confidence * 100
                                  : ioc.confidence,
                              )}
                              %
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {activeTab === "timeline" && (
              <div className="p-5 sm:p-7">
                {filteredTimeline.length === 0 ? (
                  <SharedEmptyState
                    title={search ? "No matching events" : "Timeline has no events"}
                    description={
                      search
                        ? "Try a different search term."
                        : "No timeline events are stored for this evidence. Use Build timeline to run the existing timeline service."
                    }
                  />
                ) : (
                  <div className="relative ml-2 space-y-0 border-l border-edge pl-6">
                    {filteredTimeline.map((event) => (
                      <div key={event.id} className="relative pb-8 last:pb-0">
                        <span className="absolute -left-[31px] top-1 flex h-3 w-3 rounded-full border-2 border-accent bg-surface" />
                        <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-start">
                          <div>
                            <div className="flex flex-wrap items-center gap-2">
                              <h4 className="text-sm font-medium text-content">
                                {event.title}
                              </h4>
                              <SeverityBadge value={event.severity} />
                            </div>
                            <p className="mt-2 max-w-2xl text-sm leading-6 text-content-muted">
                              {event.description}
                            </p>
                            <p className="mt-2 text-xs text-content-subtle">
                              {humanize(event.event_type)}
                              {event.source_ip ? ` · Source ${event.source_ip}` : ""}
                              {event.destination_ip ? ` · Destination ${event.destination_ip}` : ""}
                            </p>
                          </div>
                          <time className="whitespace-nowrap font-mono text-xs text-content-subtle">
                            {formatTimestamp(event.timestamp)}
                          </time>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === "mitre" && (
              <div className="grid lg:grid-cols-[minmax(0,1fr)_320px]">
                <div className="border-b border-edge p-5 sm:p-6 lg:border-b-0 lg:border-r">
                  <div className="mb-4 flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-semibold text-content">
                        Mapped techniques
                      </h4>
                      <p className="mt-1 text-xs text-content-subtle">
                        {filteredMappings.length} evidence-specific mapping(s)
                      </p>
                    </div>
                    <Target className="h-5 w-5 text-content-subtle" />
                  </div>

                  {filteredMappings.length === 0 ? (
                    <SharedEmptyState
                      title="No MITRE mappings found"
                      description={
                        search
                          ? "Try a different technique ID, tactic, or keyword."
                          : "No mappings exist for this evidence yet. Run detection analysis first, then use Map MITRE techniques."
                      }
                    />
                  ) : (
                    <div className="space-y-2">
                      {filteredMappings.map((mapping) => (
                        <button
                          key={mapping.id}
                          type="button"
                          onClick={() => setSelectedMappingId(mapping.id)}
                          className={[
                            "w-full rounded-lg border p-4 text-left transition",
                            selectedMapping?.id === mapping.id
                              ? "border-accent/50 bg-accent/[0.06]"
                              : "border-edge bg-surface-subtle/40 hover:bg-surface-subtle",
                          ].join(" ")}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <span className="font-mono text-xs text-accent">
                                {mapping.technique_id}
                              </span>
                              <h5 className="mt-1 text-sm font-medium text-content">
                                {mapping.technique_name}
                              </h5>
                              <p className="mt-1 text-xs text-content-subtle">
                                {mapping.tactic}
                              </p>
                            </div>
                            <ArrowUpRight className="h-4 w-4 shrink-0 text-accent" />
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                <div className="p-5 sm:p-6">
                  {selectedMapping ? (
                    <>
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-edge bg-surface-overlay">
                        <Target className="h-5 w-5 text-accent" />
                      </div>

                      <p className="mt-5 font-mono text-sm text-accent">
                        {selectedMapping.technique_id}
                      </p>
                      <h4 className="mt-2 text-lg font-semibold text-content">
                        {selectedMapping.technique_name}
                      </h4>

                      <p className="mt-5 text-xs uppercase tracking-wider text-content-subtle">
                        Tactic
                      </p>
                      <p className="mt-1 text-sm text-content-muted">
                        {selectedMapping.tactic}
                      </p>

                      <p className="mt-5 text-xs uppercase tracking-wider text-content-subtle">
                        Description
                      </p>
                      <p className="mt-2 text-sm leading-6 text-content-muted">
                        {selectedMapping.description ||
                          "No description provided by the mapping service."}
                      </p>

                      <p className="mt-5 text-xs uppercase tracking-wider text-content-subtle">
                        Mapping confidence
                      </p>
                      <p className="mt-1 text-sm text-content-muted">
                        {Math.round(
                          selectedMapping.confidence <= 1
                            ? selectedMapping.confidence * 100
                            : selectedMapping.confidence,
                        )}
                        %
                      </p>

                      <div className="mt-6 rounded-lg border border-severity-medium/30 bg-severity-medium/[0.06] p-4">
                        <div className="flex items-center gap-2 text-xs font-medium text-severity-medium">
                          <AlertTriangle className="h-4 w-4" />
                          Investigation context
                        </div>
                        <p className="mt-2 text-xs leading-5 text-content-muted">
                          This is a mapping returned by your backend. It is an
                          investigative lead, not independent proof that the
                          technique occurred.
                        </p>
                      </div>

                      <a
                        href={`https://attack.mitre.org/techniques/${selectedMapping.technique_id.replace(".", "/")}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-5 inline-flex items-center gap-2 text-xs text-accent hover:text-accent-muted"
                      >
                        View MITRE ATT&CK reference
                        <ArrowUpRight className="h-3.5 w-3.5" />
                      </a>
                    </>
                  ) : (
                    <SharedEmptyState
                      title="Select a mapped technique"
                      description="Choose a mapping from the list to inspect its tactic, description, and confidence."
                    />
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </Panel>

      <div className="flex items-start gap-3 rounded-lg border border-edge bg-surface-subtle/40 p-4">
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-content-subtle" />
        <p className="text-xs leading-5 text-content-subtle">
          Results are loaded for the selected case and evidence. Analysis
          actions use the existing backend services; results depend on the
          evidence, parsers, and detection rules available in your project.
        </p>
      </div>
    </div>
  );
}