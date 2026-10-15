"use client";

import { useCallback, useEffect, useState } from "react";
import { API_URL } from "@/lib/api";

import {
  IncidentReasoningPanel,
  FileForensicsPanel,
} from "@/components/nfx/InvestigationEvidencePanels";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  FileText,
  Loader2,
  RefreshCw,
  Sparkles,
  Target,
} from "lucide-react";

import {
  EmptyState,
  LoadingState,
  Panel,
  PanelHeader,
  SeverityBadge,
  StatusBadge,
  formatNumber,
  formatTimestamp,
} from "@/components/nfx/primitives";

type JsonRecord = Record<string, unknown>;

type Report = {
  report_type?: string;
  generated_at?: string;
  case?: JsonRecord;
  summary?: JsonRecord;
  evidence?: JsonRecord[];
  detections?: JsonRecord[];
  iocs?: JsonRecord[];
  timeline_events?: JsonRecord[];
  mitre_mappings?: JsonRecord[];
  limitations?: string[];
};

type Activity = {
  id: string;
  actor?: string;
  action?: string;
  details?: string;
  created_at?: string;
};

type Props = {
  caseId: string;
  evidenceId?: string;
};

type Tab =
  | "overview"
  | "ai"
  | "findings"
  | "files"
  | "timeline"
  | "report"
  | "activity";

const API_PREFIX = `${API_URL.replace(/\/+$/, "")}/api/v1`;

function fmt(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "number") return value.toLocaleString();
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function time(value: unknown): string {
  return formatTimestamp(value as number | string | null | undefined);
}

function records(value: unknown): JsonRecord[] {
  if (Array.isArray(value)) {
    return value.filter(
      (item): item is JsonRecord => typeof item === "object" && item !== null,
    );
  }
  if (typeof value === "object" && value !== null) {
    const object = value as JsonRecord;
    for (const key of ["items", "results", "data", "records"]) {
      if (Array.isArray(object[key])) return records(object[key]);
    }
  }
  return [];
}

function field(item: JsonRecord, ...keys: string[]): unknown {
  for (const key of keys) {
    if (item[key] !== undefined && item[key] !== null) return item[key];
  }
  return undefined;
}

export default function CaseInvestigationPanel({
  caseId,
  evidenceId: initialEvidenceId,
}: Props) {
  const [evidenceId, setEvidenceId] = useState(initialEvidenceId || "");
  const [tab, setTab] = useState<Tab>("overview");

  const [analysis, setAnalysis] = useState<JsonRecord | null>(null);
  const [hosts, setHosts] = useState<JsonRecord[]>([]);
  const [detections, setDetections] = useState<JsonRecord[]>([]);
  const [timeline, setTimeline] = useState<JsonRecord[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [activity, setActivity] = useState<Activity[]>([]);

  const [note, setNote] = useState("");
  const [status, setStatus] = useState("in_progress");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const call = useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      const response = await fetch(`${API_PREFIX}${path}`, {
        ...init,
        headers: {
          ...(init?.body ? { "Content-Type": "application/json" } : {}),
          ...init?.headers,
        },
        cache: "no-store",
      });

      if (!response.ok) {
        const body = await response.text();
        throw new Error(`API ${response.status}: ${body.slice(0, 250)}`);
      }

      return response.json() as Promise<T>;
    },
    [],
  );

  const evidencePath = useCallback(
    (resource: string) =>
      `/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(
        evidenceId,
      )}/${resource}`,
    [caseId, evidenceId],
  );

  const loadReport = useCallback(async () => {
    const params = new URLSearchParams();
    if (evidenceId.trim()) params.set("evidence_id", evidenceId.trim());
    const query = params.size ? `?${params.toString()}` : "";

    const result = await call<Report>(
      `/reports/cases/${encodeURIComponent(caseId)}${query}`,
    );
    setReport(result);
  }, [call, caseId, evidenceId]);

  const loadActivity = useCallback(async () => {
    const result = await call<{ items?: Activity[] }>(
      `/cases/${encodeURIComponent(caseId)}/activity`,
    );
    setActivity(Array.isArray(result.items) ? result.items : []);
  }, [call, caseId]);

  const loadInvestigation = useCallback(async () => {
    if (!caseId) throw new Error("A case ID is required.");
    if (!evidenceId.trim()) {
      throw new Error("Enter or select an evidence ID to load the investigation.");
    }

    setLoading(true);
    setError("");
    setMessage("");

    const results = await Promise.allSettled([
      call<JsonRecord>(evidencePath("analysis")),
      call<unknown>(evidencePath("hosts")),
      call<unknown>(evidencePath("detections?limit=500")),
      call<unknown>(evidencePath("timeline?limit=1000")),
      loadReport(),
    ]);

    const failures: string[] = [];

    if (results[0].status === "fulfilled") setAnalysis(results[0].value);
    else failures.push("Analysis could not be loaded.");

    if (results[1].status === "fulfilled") setHosts(records(results[1].value));
    else failures.push("Hosts could not be loaded.");

    if (results[2].status === "fulfilled") setDetections(records(results[2].value));
    else failures.push("Detections could not be loaded.");

    if (results[3].status === "fulfilled") setTimeline(records(results[3].value));
    else failures.push("Timeline could not be loaded.");

    if (results[4].status === "rejected") {
      failures.push("Report could not be loaded.");
    }

    if (failures.length) setError(failures.join(" "));
    else setMessage("Investigation data refreshed.");

    setLoading(false);
  }, [caseId, evidenceId, call, evidencePath, loadReport]);

  const refreshCurrentTab = useCallback(async () => {
    setLoading(true);
    setError("");
    setMessage("");

    try {
      if (tab === "activity") await loadActivity();
      else if (tab === "report") await loadReport();
      else {
        await loadInvestigation();
        return;
      }

      setMessage("Data refreshed.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed.");
    } finally {
      setLoading(false);
    }
  }, [tab, loadActivity, loadReport, loadInvestigation]);

  useEffect(() => {
    setEvidenceId(initialEvidenceId || "");
  }, [initialEvidenceId]);

  useEffect(() => {
    if (initialEvidenceId && caseId) void loadInvestigation();
  }, [initialEvidenceId, caseId, loadInvestigation]);

  async function addNote() {
    if (!note.trim()) {
      setError("Enter a note first.");
      return;
    }

    setLoading(true);
    setError("");
    setMessage("");

    try {
      await call(`/cases/${encodeURIComponent(caseId)}/activity`, {
        method: "POST",
        body: JSON.stringify({
          actor: "analyst",
          action: "note_added",
          details: note.trim(),
        }),
      });

      setNote("");
      await loadActivity();
      setMessage("Analyst note saved.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save note.");
    } finally {
      setLoading(false);
    }
  }

  async function updateStatus() {
    setLoading(true);
    setError("");
    setMessage("");

    try {
      await call(`/cases/${encodeURIComponent(caseId)}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status, actor: "analyst" }),
      });

      await loadActivity();
      setMessage("Case status updated.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update case status.");
    } finally {
      setLoading(false);
    }
  }

  async function exportReport(format: "json" | "pdf") {
    setLoading(true);
    setError("");
    setMessage("");

    try {
      const params = new URLSearchParams();
      if (evidenceId.trim()) params.set("evidence_id", evidenceId.trim());
      const query = params.size ? `?${params.toString()}` : "";

      const response = await fetch(
        `${API_PREFIX}/reports/cases/${encodeURIComponent(caseId)}/export.${format}${query}`,
        { cache: "no-store" },
      );

      if (!response.ok) {
        const body = await response.text();
        throw new Error(
          `Export failed (${response.status}): ${body.slice(0, 250)}`,
        );
      }

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `case-${caseId}-report.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setMessage(`${format.toUpperCase()} report downloaded.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Report export failed.");
    } finally {
      setLoading(false);
    }
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "ai", label: "AI Investigation" },
    { id: "findings", label: "Threat Findings" },
    { id: "files", label: "File Forensics" },
    { id: "timeline", label: "Timeline" },
    { id: "report", label: "Forensic Report" },
    { id: "activity", label: "Case Activity" },
  ];

  const iocs = report?.iocs || [];
  const mitreMappings = report?.mitre_mappings || [];
  const evidence = report?.evidence || [];
  const reportDetections = report?.detections || detections;
  const reportTimeline = report?.timeline_events || timeline;
  const summary = report?.summary || {};

  const detectionCount = Math.max(
    detections.length,
    report?.detections?.length || 0,
  );

  const criticalCount = detections.filter((item) =>
    String(field(item, "severity", "level") ?? "").toLowerCase().includes("critical"),
  ).length;

  const highCount = detections.filter((item) =>
    String(field(item, "severity", "level") ?? "").toLowerCase().includes("high"),
  ).length;

  return (
    <section className="mt-4 space-y-5 text-content">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-accent">
            NetForensicX · Digital Forensics
          </p>
          <h2 className="mt-2 text-2xl font-semibold text-content">
            Case Investigation
          </h2>
          <p className="mt-2 max-w-2xl text-sm text-content-muted">
            Investigate evidence, review detections, correlate events, and
            prepare a forensic report in one workspace.
          </p>
          <p className="mt-3 break-all font-mono text-xs text-content-subtle">
            Case ID: {caseId}
          </p>
        </div>

        <button
          type="button"
          onClick={() => void refreshCurrentTab()}
          disabled={loading}
          className="inline-flex h-9 items-center gap-2 rounded-lg border border-edge bg-surface-subtle px-3 text-xs font-medium text-content-muted transition hover:border-edge-strong hover:text-content disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Refreshing…" : "Refresh data"}
        </button>
      </div>

      <Panel elevated>
        <div className="grid gap-3 p-5 md:grid-cols-[1fr_auto] md:items-end">
          <label>
            <span className="mb-2 block text-xs font-medium text-content-subtle">
              Evidence ID
            </span>
            <input
              value={evidenceId}
              onChange={(event) => setEvidenceId(event.target.value)}
              placeholder="Enter evidence UUID"
              className="w-full rounded-lg border border-edge bg-surface px-3 py-3 text-sm text-content outline-none placeholder:text-content-subtle focus:border-accent"
            />
          </label>

          <button
            type="button"
            onClick={() => void loadInvestigation()}
            disabled={loading || !evidenceId.trim()}
            className="inline-flex h-11 items-center gap-2 rounded-lg bg-accent px-4 text-sm font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            {loading ? "Loading…" : "Load investigation"}
          </button>
        </div>
      </Panel>

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-severity-critical/30 bg-severity-critical/10 p-3 text-sm text-severity-critical"
        >
          {error}
        </div>
      )}

      {message && (
        <div
          role="status"
          className="rounded-lg border border-status-verified/30 bg-status-verified/10 p-3 text-sm text-status-verified"
        >
          {message}
        </div>
      )}

      {/* Pill tab rail — visible active state */}
      <nav className="nfx-tab-rail">
        {tabs.map((item) => {
          const active = tab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              data-active={active}
              onClick={() => {
                setTab(item.id);
                setError("");
                setMessage("");
                if (item.id === "activity") void loadActivity().catch(() => {});
                if (item.id === "report") void loadReport().catch(() => {});
              }}
              className="nfx-tab"
            >
              {item.label}
            </button>
          );
        })}
      </nav>

      {tab === "overview" && (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {[
              {
                label: "Evidence records",
                value: evidence.length,
                detail: "Included in the report",
              },
              {
                label: "Threat detections",
                value: detectionCount,
                detail: "Available detection records",
              },
              {
                label: "Critical findings",
                value: criticalCount,
                detail: "Explicitly marked critical",
              },
              {
                label: "High findings",
                value: highCount,
                detail: "Explicitly marked high",
              },
            ].map((item) => (
              <div
                key={item.label}
                className="rounded-xl border border-edge bg-surface-subtle/60 p-5 transition hover:border-edge-strong"
              >
                <p className="text-xs uppercase tracking-wider text-content-subtle">
                  {item.label}
                </p>
                <p className="mt-3 text-3xl font-semibold text-content tabular-nums">
                  {fmt(item.value)}
                </p>
                <p className="mt-2 text-xs text-content-subtle">{item.detail}</p>
              </div>
            ))}
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <Panel>
              <PanelHeader
                icon={<Database className="h-5 w-5" />}
                title="Investigation status"
                description={
                  analysis
                    ? "Analysis data is available for the selected evidence."
                    : "Load evidence to retrieve its analysis status."
                }
              />
              <div className="space-y-3 p-5">
                {Object.entries(analysis || {}).slice(0, 10).map(([key, value]) => (
                  <div
                    key={key}
                    className="flex flex-wrap justify-between gap-3 border-b border-edge pb-3 last:border-b-0"
                  >
                    <span className="text-sm text-content-muted">
                      {key.replace(/_/g, " ")}
                    </span>
                    <span className="max-w-[65%] break-all text-right text-sm text-content">
                      {fmt(value)}
                    </span>
                  </div>
                ))}
                {!analysis && (
                  <p className="text-sm text-content-subtle">
                    No analysis metadata loaded.
                  </p>
                )}
              </div>
            </Panel>

            <Panel>
              <PanelHeader
                icon={<FileText className="h-5 w-5" />}
                title="Evidence integrity"
                description="Stored hashes and metadata from the report."
              />
              <div className="p-5">
                {evidence.length ? (
                  <div className="space-y-4">
                    {evidence.map((item, index) => (
                      <div
                        key={String(field(item, "id") ?? index)}
                        className="rounded-lg border border-edge p-3"
                      >
                        <p className="break-all text-sm font-medium text-content">
                          {fmt(field(item, "filename", "original_filename"))}
                        </p>
                        <p className="mt-2 break-all font-mono text-xs text-content-muted">
                          SHA-256: {fmt(field(item, "sha256", "file_hash"))}
                        </p>
                        <p className="mt-2 text-xs text-content-subtle">
                          Size: {fmt(field(item, "size_bytes", "size"))} · Added:{" "}
                          {time(field(item, "created_at"))}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-content-subtle">
                    Evidence metadata will appear here when the report includes
                    evidence records.
                  </p>
                )}

                <p className="mt-4 text-xs leading-5 text-content-subtle">
                  A stored hash is useful for integrity tracking, but this panel
                  does not independently re-hash the source file.
                </p>
              </div>
            </Panel>
          </div>

          <Panel>
            <PanelHeader
              title="Investigation snapshot"
              description="Counts supplied by the current forensic report."
              actions={
                <button
                  type="button"
                  onClick={() => setTab("report")}
                  className="inline-flex h-8 items-center rounded-lg border border-edge bg-surface-subtle px-3 text-[11px] font-medium text-content-muted transition hover:border-edge-strong hover:text-content"
                >
                  Open report
                </button>
              }
            />
            <div className="grid gap-3 p-5 sm:grid-cols-2 lg:grid-cols-3">
              {Object.entries(summary).map(([key, value]) => (
                <div key={key} className="rounded-lg bg-surface-overlay/60 p-4">
                  <p className="text-xs capitalize text-content-subtle">
                    {key.replace(/_/g, " ")}
                  </p>
                  <p className="mt-2 break-words text-lg text-content">
                    {fmt(value)}
                  </p>
                </div>
              ))}
              {!Object.keys(summary).length && (
                <p className="text-sm text-content-subtle">
                  Load investigation data to populate the summary.
                </p>
              )}
            </div>
          </Panel>
        </div>
      )}

      {tab === "ai" && (
  <IncidentReasoningPanel
    caseId={caseId}
    evidenceId={evidenceId || undefined}
  />
)}

      {tab === "findings" && (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-edge bg-surface-subtle/60 p-5">
              <p className="text-xs uppercase tracking-wider text-content-subtle">
                Detections
              </p>
              <p className="mt-2 text-2xl font-semibold text-content tabular-nums">
                {detectionCount}
              </p>
            </div>
            <div className="rounded-xl border border-edge bg-surface-subtle/60 p-5">
              <p className="text-xs uppercase tracking-wider text-content-subtle">
                IOCs
              </p>
              <p className="mt-2 text-2xl font-semibold text-content tabular-nums">
                {iocs.length}
              </p>
            </div>
            <div className="rounded-xl border border-edge bg-surface-subtle/60 p-5">
              <p className="text-xs uppercase tracking-wider text-content-subtle">
                ATT&CK mappings
              </p>
              <p className="mt-2 text-2xl font-semibold text-content tabular-nums">
                {mitreMappings.length}
              </p>
            </div>
          </div>

          <Panel>
            <PanelHeader
              title="Detection findings"
              description={`${reportDetections.length} records from the report or investigation load.`}
            />
            <div className="space-y-3 p-5">
              {reportDetections.map((item, index) => {
                const severity = field(item, "severity", "level");
                return (
                  <div
                    key={String(field(item, "id") ?? index)}
                    className="rounded-lg border border-edge p-4"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <p className="font-medium text-content">
                        {fmt(field(item, "title", "name", "rule_name"))}
                      </p>
                      <SeverityBadge value={String(severity ?? "")} />
                    </div>
                    <p className="mt-2 text-sm leading-6 text-content-muted">
                      {fmt(field(item, "description", "message"))}
                    </p>
                    <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs text-content-subtle">
                      <span>
                        Source: {fmt(field(item, "source_ip", "src_ip"))}
                      </span>
                      <span>
                        Destination: {fmt(field(item, "destination_ip", "dst_ip"))}
                      </span>
                      <span>
                        Time:{" "}
                        {time(field(item, "timestamp", "created_at", "first_seen"))}
                      </span>
                      <span>Confidence: {fmt(field(item, "confidence"))}</span>
                    </div>
                  </div>
                );
              })}
              {!reportDetections.length && (
                <p className="py-8 text-center text-sm text-content-subtle">
                  No detection records are currently available.
                </p>
              )}
            </div>
          </Panel>

          <Panel>
            <PanelHeader
              title="Indicators of compromise"
              description="IOC records included in the current report."
            />
            <div className="space-y-3 p-5">
              {iocs.map((item, index) => (
                <div
                  key={String(field(item, "id") ?? index)}
                  className="rounded-lg border border-edge p-3"
                >
                  <p className="break-all font-mono text-sm text-accent">
                    {fmt(field(item, "value", "indicator"))}
                  </p>
                  <p className="mt-2 text-xs text-content-subtle">
                    Type: {fmt(field(item, "ioc_type", "type"))} · Severity:{" "}
                    {fmt(field(item, "severity"))}
                  </p>
                </div>
              ))}
              {!iocs.length && (
                <p className="text-sm text-content-subtle">
                  No IOCs are included in the current report.
                </p>
              )}
            </div>
          </Panel>

          <Panel>
            <PanelHeader
              title="MITRE ATT&CK mappings"
              description="Technique mappings produced by the backend."
            />
            <div className="grid gap-3 p-5 md:grid-cols-2">
              {mitreMappings.map((item, index) => (
                <div
                  key={String(field(item, "id") ?? index)}
                  className="rounded-lg border border-edge p-4"
                >
                  <p className="font-mono text-sm text-accent">
                    {fmt(field(item, "technique_id", "technique"))}
                  </p>
                  <p className="mt-2 font-medium text-content">
                    {fmt(field(item, "technique_name", "name"))}
                  </p>
                  <p className="mt-2 text-xs text-content-subtle">
                    Tactic: {fmt(field(item, "tactic"))}
                  </p>
                </div>
              ))}
              {!mitreMappings.length && (
                <p className="text-sm text-content-subtle">
                  No ATT&CK mappings are included in the current report.
                </p>
              )}
            </div>
          </Panel>
        </div>
      )}

      {tab === "files" && (
  <FileForensicsPanel
    caseId={caseId}
    evidenceId={evidenceId || undefined}
  />
)}

      {tab === "timeline" && (
        <Panel>
          <PanelHeader
            title="Investigation timeline"
            description={`${reportTimeline.length} events from the timeline and report services.`}
          />
          <div className="p-5">
            <div className="relative ml-2 space-y-0 border-l border-edge pl-6">
              {reportTimeline.map((item, index) => (
                <div key={String(field(item, "id") ?? index)} className="relative pb-6 last:pb-0">
                  <span className="absolute -left-[31px] top-1 flex h-3 w-3 rounded-full border-2 border-accent bg-surface" />
                  <p className="text-xs text-accent">
                    {time(field(item, "timestamp", "event_time", "created_at"))}
                  </p>
                  <p className="mt-2 font-medium text-content">
                    {fmt(field(item, "title", "event_type", "name", "description"))}
                  </p>
                  <p className="mt-2 text-sm leading-6 text-content-muted">
                    {fmt(field(item, "details", "description", "message"))}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-content-subtle">
                    <span>Source: {fmt(field(item, "source_ip", "src_ip"))}</span>
                    <span>
                      Destination:{" "}
                      {fmt(field(item, "destination_ip", "dst_ip"))}
                    </span>
                    <span>Type: {fmt(field(item, "event_type", "type"))}</span>
                  </div>
                </div>
              ))}
              {!reportTimeline.length && (
                <p className="py-10 text-center text-sm text-content-subtle">
                  No timeline events are available. Load investigation data and
                  verify that timeline events have been generated.
                </p>
              )}
            </div>
          </div>
        </Panel>
      )}

      {tab === "report" && (
        <div className="space-y-5">
          <Panel>
            <PanelHeader
              title="Forensic report"
              description={`Generated: ${time(report?.generated_at)}`}
              actions={
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      void loadReport()
                        .then(() => setMessage("Report refreshed."))
                        .catch((err) =>
                          setError(
                            err instanceof Error
                              ? err.message
                              : "Unable to load report.",
                          ),
                        )
                    }
                    disabled={loading}
                    className="inline-flex h-8 items-center rounded-lg border border-edge bg-surface-subtle px-3 text-[11px] font-medium text-content-muted transition hover:border-edge-strong hover:text-content disabled:opacity-50"
                  >
                    Preview
                  </button>
                  <button
                    type="button"
                    onClick={() => void exportReport("json")}
                    disabled={loading}
                    className="inline-flex h-8 items-center rounded-lg border border-edge bg-surface-subtle px-3 text-[11px] font-medium text-content-muted transition hover:border-edge-strong hover:text-content disabled:opacity-50"
                  >
                    Export JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => void exportReport("pdf")}
                    disabled={loading}
                    className="inline-flex h-8 items-center rounded-lg bg-accent px-3 text-[11px] font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:opacity-50"
                  >
                    Export PDF
                  </button>
                </div>
              }
            />
            <div className="grid gap-3 p-5 sm:grid-cols-2 lg:grid-cols-3">
              {Object.entries(summary).map(([key, value]) => (
                <div key={key} className="rounded-lg bg-surface-overlay/60 p-4">
                  <p className="text-xs capitalize text-content-subtle">
                    {key.replace(/_/g, " ")}
                  </p>
                  <p className="mt-2 break-words text-lg text-content">
                    {fmt(value)}
                  </p>
                </div>
              ))}
              {!Object.keys(summary).length && (
                <p className="text-sm text-content-subtle">
                  Load the report to preview summary values.
                </p>
              )}
            </div>
          </Panel>

          {!!report?.limitations?.length && (
            <Panel>
              <PanelHeader title="Report limitations" />
              <ul className="list-disc space-y-2 p-5 pl-9 text-sm leading-6 text-content-muted">
                {report.limitations.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </Panel>
          )}

          <Panel>
            <PanelHeader title="Report completeness" />
            <p className="p-5 text-sm leading-6 text-content-muted">
              The current report endpoint provides structured database records.
              The PDF generator still needs further development to include a
              grounded AI narrative, complete timeline, recovered-file
              artifacts, and all supporting evidence. Exporting a PDF does not
              by itself mean those capabilities have been implemented.
            </p>
          </Panel>
        </div>
      )}

      {tab === "activity" && (
        <div className="grid gap-5 lg:grid-cols-2">
          <Panel>
            <PanelHeader
              title="Update investigation"
              description="Change status and record analyst notes."
            />
            <div className="space-y-4 p-5">
              <div>
                <label className="mb-2 block text-xs text-content-subtle">
                  Case status
                </label>
                <select
                  value={status}
                  onChange={(event) => setStatus(event.target.value)}
                  className="w-full rounded-lg border border-edge bg-surface px-3 py-3 text-sm text-content outline-none focus:border-accent"
                >
                  <option value="open">Open</option>
                  <option value="in_progress">In progress</option>
                  <option value="under_review">Under review</option>
                  <option value="closed">Closed</option>
                </select>
                <button
                  type="button"
                  onClick={() => void updateStatus()}
                  disabled={loading}
                  className="mt-3 inline-flex h-10 w-full items-center justify-center rounded-lg border border-edge bg-surface-subtle text-sm font-medium text-content-muted transition hover:border-edge-strong hover:text-content disabled:opacity-50"
                >
                  Update status
                </button>
              </div>

              <div>
                <label className="mb-2 block text-xs text-content-subtle">
                  Analyst note
                </label>
                <textarea
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  rows={5}
                  placeholder="Record an observation, hypothesis, or investigation decision…"
                  className="w-full rounded-lg border border-edge bg-surface px-3 py-3 text-sm text-content outline-none placeholder:text-content-subtle focus:border-accent"
                />
                <button
                  type="button"
                  onClick={() => void addNote()}
                  disabled={loading || !note.trim()}
                  className="mt-3 inline-flex h-10 w-full items-center justify-center rounded-lg bg-accent text-sm font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:opacity-50"
                >
                  Save analyst note
                </button>
              </div>
            </div>
          </Panel>

          <Panel>
            <PanelHeader
              title="Activity history"
              description={`${activity.length} records`}
              actions={
                <button
                  type="button"
                  onClick={() => void loadActivity()}
                  disabled={loading}
                  className="inline-flex h-8 items-center rounded-lg border border-edge bg-surface-subtle px-3 text-[11px] font-medium text-content-muted transition hover:border-edge-strong hover:text-content disabled:opacity-50"
                >
                  Refresh history
                </button>
              }
            />
            <div className="space-y-3 p-5">
              {activity.map((item) => (
                <div
                  key={item.id}
                  className="rounded-lg border border-edge p-4"
                >
                  <div className="flex flex-wrap justify-between gap-2">
                    <p className="text-sm font-medium text-content">
                      {(item.action || "Activity").replace(/_/g, " ")}
                    </p>
                    <p className="text-xs text-content-subtle">
                      {time(item.created_at)}
                    </p>
                  </div>
                  <p className="mt-2 text-xs text-accent">
                    {item.actor || "Analyst"}
                  </p>
                  <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-content-muted">
                    {item.details || "—"}
                  </p>
                </div>
              ))}
              {!activity.length && (
                <p className="py-8 text-center text-sm text-content-subtle">
                  No activity records loaded.
                </p>
              )}
            </div>
          </Panel>
        </div>
      )}
    </section>
  );
}