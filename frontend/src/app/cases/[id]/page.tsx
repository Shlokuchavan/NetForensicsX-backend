"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Box,
  ChevronDown,
  ChevronLeft,
  Clock3,
  FileText,
  Globe,
  Lock,
  Network,
  Play,
  RefreshCw,
  Search,
  Server,
  Share2,
  Shield,
  ShieldAlert,
  Upload,
} from "lucide-react";

import CaseIntelligenceTabs from "./CaseIntelligenceTabs";
import CaseInvestigationPanel from "./CaseInvestigationPanel";

import {
  analyzeDNS,
  analyzeEvidence,
  analyzeHTTP,
  analyzeTLS,
  discoverHosts,
  getCaseById,
  getCaseEvidence,
  getCases,
  getDiscoveredHosts,
  getDNSRecords,
  getEvidenceAnalysis,
  getEvidenceFlows,
  getHTTPTransactions,
  getNetworkTopology,
  getTLSSessions,
  uploadEvidence,
} from "@/lib/api";

import type {
  Case,
  DNSRecord,
  Evidence,
  HTTPTransaction,
  NetworkFlow,
  NetworkHost,
  NetworkTopology,
  PcapAnalysis,
  TLSSession,
} from "@/lib/api";

import {
  EmptyState,
  ErrorState,
  InlineCheck,
  LoadingState,
  MetricCard,
  Panel,
  PanelHeader,
  SectionHeader,
  SeverityBadge,
  StatusBadge,
  formatBytes,
  formatDuration,
  formatNumber,
  formatTimestamp,
  humanize,
} from "@/components/nfx/primitives";

/* =========================================================
   TYPES
========================================================= */

type TabId =
  | "overview"
  | "evidence"
  | "analysis"
  | "hosts"
  | "flows"
  | "topology"
  | "protocols"
  | "investigation"
  | "detections";

type ProtocolTab = "dns" | "http" | "tls";

type TopologyZone = "internal" | "infrastructure" | "external";

type TopologyPosition = { x: number; y: number };

/* =========================================================
   TAB DEFINITION
========================================================= */

const TAB_GROUPS: {
  label: string;
  items: { id: TabId; label: string; icon: React.ElementType }[];
}[] = [
  {
    label: "Workspace",
    items: [
      { id: "overview", label: "Overview", icon: Activity },
      { id: "evidence", label: "Evidence", icon: FileText },
      { id: "analysis", label: "PCAP Analysis", icon: Box },
    ],
  },
  {
    label: "Investigation",
    items: [
      { id: "hosts", label: "Hosts", icon: Server },
      { id: "flows", label: "Network Flows", icon: Network },
      { id: "topology", label: "Topology", icon: Share2 },
      { id: "protocols", label: "Protocols", icon: Shield },
    ],
  },
  {
    label: "Threat analysis",
    items: [
      { id: "detections", label: "Security Intelligence", icon: ShieldAlert },
      { id: "investigation", label: "Case Investigation", icon: Search },
    ],
  },
];

const ALL_TABS = TAB_GROUPS.flatMap((g) => g.items);

/* =========================================================
   HELPERS
========================================================= */

function isPrivateIP(ip: string): boolean {
  const value = ip.trim();
  if (value === "localhost" || value === "127.0.0.1" || value === "::1") return true;
  if (value.startsWith("10.") || value.startsWith("192.168.")) return true;
  if (value.startsWith("172.")) {
    const second = Number(value.split(".")[1]);
    if (second >= 16 && second <= 31) return true;
  }
  if (value.startsWith("169.254.")) return true;
  if (value.startsWith("fc") || value.startsWith("fd")) return true;
  return false;
}

function isDNSNode(node: NetworkTopology["nodes"][number]): boolean {
  const value = `${node.id} ${node.label}`.toLowerCase();
  return value.includes("dns") || value.includes(":53") || value.includes("domain");
}

function classifyNode(node: NetworkTopology["nodes"][number]): TopologyZone {
  if (isDNSNode(node)) return "infrastructure";
  if (isPrivateIP(node.id)) return "internal";
  return "external";
}

/* =========================================================
   OVERVIEW TAB
========================================================= */

function OverviewTab({
  evidence,
  analysisMap,
  selectedEvidence,
  analysis,
  hosts,
  flows,
  dnsRecords,
  httpTransactions,
  tlsSessions,
  onSelectEvidence,
  onAnalyze,
}: {
  evidence: Evidence[];
  analysisMap: Record<string, PcapAnalysis | null>;
  selectedEvidence: Evidence | null;
  analysis: PcapAnalysis | null;
  hosts: NetworkHost[];
  flows: NetworkFlow[];
  dnsRecords: DNSRecord[];
  httpTransactions: HTTPTransaction[];
  tlsSessions: TLSSession[];
  onSelectEvidence: (id: string) => void;
  onAnalyze: (id: string) => void;
}) {
  const analyzedCount = Object.values(analysisMap).filter(Boolean).length;

  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard
          label="Evidence files"
          value={formatNumber(evidence.length)}
          description="PCAPs attached to this case"
          icon={<FileText className="h-4 w-4" />}
          className="nfx-metric"
        />
        <MetricCard
          label="Analyzed"
          value={formatNumber(analyzedCount)}
          description="Successfully processed"
          icon={<Activity className="h-4 w-4" />}
          className="nfx-metric"
        />
        <MetricCard
          label="Packets"
          value={analysis ? formatNumber(analysis.packet_count) : "—"}
          description="In active capture"
          icon={<Activity className="h-4 w-4" />}
          className="nfx-metric"
        />
        <MetricCard
          label="Hosts"
          value={analysis ? formatNumber(analysis.host_count) : "—"}
          description="Unique addresses"
          icon={<Server className="h-4 w-4" />}
          className="nfx-metric"
        />
        <MetricCard
          label="Flows"
          value={analysis ? formatNumber(analysis.flow_count) : "—"}
          description="Aggregated conversations"
          icon={<Network className="h-4 w-4" />}
          className="nfx-metric"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.5fr_1fr]">
        <Panel elevated className="nfx-panel-enter nfx-panel-hover">
          <PanelHeader
            icon={<Shield className="h-5 w-5" />}
            title="Investigation summary"
            description="Current state of the selected evidence."
          />
          <div className="p-6">
            {analysis ? (
              <div className="grid gap-5 sm:grid-cols-2">
                <div>
                  <p className="text-xs text-content-subtle">Capture duration</p>
                  <p className="mt-1 font-medium text-content tabular-nums">
                    {formatDuration(analysis.duration)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-content-subtle">Packets</p>
                  <p className="mt-1 font-medium text-content tabular-nums">
                    {formatNumber(analysis.packet_count)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-content-subtle">TCP traffic</p>
                  <p className="mt-1 font-medium text-content tabular-nums">
                    {formatNumber(analysis.tcp_count)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-content-subtle">UDP traffic</p>
                  <p className="mt-1 font-medium text-content tabular-nums">
                    {formatNumber(analysis.udp_count)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-content-subtle">DNS queries</p>
                  <p className="mt-1 font-medium text-content tabular-nums">
                    {formatNumber(analysis.dns_count)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-content-subtle">HTTP / HTTPS</p>
                  <p className="mt-1 font-medium text-content tabular-nums">
                    {formatNumber(analysis.http_count)} /{" "}
                    {formatNumber(analysis.https_count)}
                  </p>
                </div>
              </div>
            ) : (
              <EmptyState
                title="No analysis selected"
                description="Analyze a PCAP to populate investigation metrics."
              />
            )}
          </div>
        </Panel>

        <Panel elevated className="nfx-panel-enter nfx-panel-hover">
          <PanelHeader
            icon={<FileText className="h-5 w-5" />}
            title="Selected evidence"
            description="Active investigation source."
          />
          <div className="p-6">
            {selectedEvidence ? (
              <>
                <p className="break-all text-sm font-medium text-content">
                  {selectedEvidence.original_filename}
                </p>
                <p className="mt-2 text-xs text-content-muted">
                  {formatBytes(selectedEvidence.file_size)} ·{" "}
                  {humanize(selectedEvidence.status)}
                </p>
                <div className="mt-4 rounded-lg border border-edge bg-surface-overlay p-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-content-subtle">
                    SHA-256
                  </p>
                  <p className="mt-1 break-all font-mono text-[10px] leading-5 text-content-muted">
                    {selectedEvidence.sha256}
                  </p>
                </div>
              </>
            ) : (
              <p className="text-sm text-content-subtle">No evidence available.</p>
            )}
          </div>
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel className="nfx-panel-enter nfx-panel-hover">
          <PanelHeader
            title="Analysis pipeline"
            description="Progress across the analysis stages."
          />
          <div className="space-y-2 p-5">
            {(
              [
                ["PCAP ingestion", Boolean(analysis)],
                ["Host discovery", hosts.length > 0],
                ["Flow extraction", flows.length > 0],
                ["DNS analysis", dnsRecords.length > 0 || Boolean(analysis?.dns_count)],
                ["HTTP analysis", httpTransactions.length > 0 || Boolean(analysis?.http_count)],
                ["TLS analysis", tlsSessions.length > 0 || Boolean(analysis?.https_count)],
              ] as [string, boolean][]
            ).map(([label, complete]) => (
              <div
                key={label}
                className="flex items-center justify-between rounded-lg border border-edge px-3 py-2.5 transition hover:border-edge-strong"
              >
                <span className="text-xs text-content-muted">{label}</span>
                <InlineCheck ok={complete} />
              </div>
            ))}
          </div>
        </Panel>

        <Panel className="nfx-panel-enter nfx-panel-hover">
          <PanelHeader
            title="Capture window"
            description="Original packet capture period."
          />
          <div className="p-5">
            {analysis ? (
              <div className="space-y-5">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-content-subtle">
                    Start
                  </p>
                  <p className="mt-1 text-sm text-content">
                    {formatTimestamp(analysis.capture_start)}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-content-subtle">
                    End
                  </p>
                  <p className="mt-1 text-sm text-content">
                    {formatTimestamp(analysis.capture_end)}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-content-subtle">
                    Duration
                  </p>
                  <p className="mt-1 text-sm text-content tabular-nums">
                    {formatDuration(analysis.duration)}
                  </p>
                </div>
              </div>
            ) : (
              <p className="text-sm text-content-subtle">
                No capture window available.
              </p>
            )}
          </div>
        </Panel>
      </div>

      <Panel className="nfx-panel-enter">
        <PanelHeader
          title="Evidence"
          description="Select a PCAP to make it the active investigation source."
        />
        {evidence.length === 0 ? (
          <EmptyState
            title="No evidence uploaded"
            description="Upload a PCAP from the Evidence tab to begin."
          />
        ) : (
          <div className="divide-y divide-edge">
            {evidence.map((item) => {
              const selected = selectedEvidence?.id === item.id;
              const itemAnalysis = analysisMap[item.id];
              return (
                <div
                  key={item.id}
                  className={[
                    "flex flex-col gap-4 p-5 transition sm:flex-row sm:items-center sm:justify-between",
                    selected
                      ? "bg-surface-overlay/60"
                      : "hover:bg-surface-overlay/40",
                  ].join(" ")}
                >
                  <button
                    type="button"
                    onClick={() => onSelectEvidence(item.id)}
                    className="min-w-0 text-left"
                  >
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-surface-overlay text-content-muted">
                        <FileText className="h-4 w-4" />
                      </div>
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-content">
                          {item.original_filename}
                        </p>
                        <p className="mt-1 text-xs text-content-subtle">
                          {formatBytes(item.file_size)} ·{" "}
                          {itemAnalysis ? "Analyzed" : "Not analyzed"}
                        </p>
                      </div>
                    </div>
                  </button>
                  <div className="flex items-center gap-2">
                    {selected && <StatusBadge value="Active" tone="verified" />}
                    {!itemAnalysis && (
                      <button
                        type="button"
                        onClick={() => onAnalyze(item.id)}
                        className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-xs font-semibold text-accent-foreground transition hover:bg-accent-muted"
                      >
                        <Play className="h-3.5 w-3.5" />
                        Analyze
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Panel>
    </div>
  );
}

/* =========================================================
   EVIDENCE TAB
========================================================= */

function EvidenceTab({
  evidence,
  selectedEvidenceId,
  analysisMap,
  onSelect,
  onAnalyze,
  onUpload,
  uploading,
  analyzingId,
}: {
  evidence: Evidence[];
  selectedEvidenceId: string | null;
  analysisMap: Record<string, PcapAnalysis | null>;
  onSelect: (id: string) => void;
  onAnalyze: (id: string) => void;
  onUpload: (event: React.ChangeEvent<HTMLInputElement>) => void;
  uploading: boolean;
  analyzingId: string | null;
}) {
  return (
    <div className="space-y-6">
      <Panel elevated className="nfx-panel-enter">
        <div className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-semibold text-content">
              Evidence intake
            </h2>
            <p className="mt-1 text-sm text-content-muted">
              Upload PCAP evidence associated with this case. Files are hashed
              by the backend on receipt.
            </p>
          </div>
          <label className="inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-accent-foreground transition hover:bg-accent-muted">
            <Upload className="h-4 w-4" />
            {uploading ? "Uploading…" : "Upload PCAP"}
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              className="hidden"
              disabled={uploading}
              onChange={onUpload}
            />
          </label>
        </div>
      </Panel>

      {evidence.length === 0 ? (
        <Panel className="nfx-panel-enter">
          <EmptyState
            title="No evidence uploaded"
            description="Upload a PCAP or PCAPNG file to begin the forensic investigation."
          />
        </Panel>
      ) : (
        <div className="grid gap-3">
          {evidence.map((item, index) => {
            const selected = item.id === selectedEvidenceId;
            const itemAnalysis = analysisMap[item.id];
            return (
              <Panel
                key={item.id}
                className={[
                  "nfx-panel-enter nfx-panel-hover",
                  selected ? "ring-1 ring-accent/40" : "",
                ].join(" ")}
              >
                <div className="flex flex-col gap-5 p-5 lg:flex-row lg:items-start lg:justify-between">
                  <button
                    type="button"
                    onClick={() => onSelect(item.id)}
                    className="min-w-0 flex-1 text-left"
                  >
                    <div className="flex items-start gap-4">
                      <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-surface-overlay text-content-muted transition group-hover:text-accent">
                        <FileText className="h-5 w-5" />
                      </div>
                      <div className="min-w-0">
                        <p className="break-all text-sm font-semibold text-content">
                          {item.original_filename}
                        </p>
                        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-content-subtle">
                          <span className="tabular-nums">
                            {formatBytes(item.file_size)}
                          </span>
                          <span>{humanize(item.status)}</span>
                          <span>
                            {new Date(item.created_at).toLocaleString()}
                          </span>
                        </div>
                      </div>
                    </div>
                  </button>
                  <div className="flex shrink-0 items-center gap-2">
                    {selected && <StatusBadge value="Active" tone="verified" />}
                    <button
                      type="button"
                      onClick={() => onAnalyze(item.id)}
                      disabled={analyzingId === item.id}
                      className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-xs font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <Play className="h-3.5 w-3.5" />
                      {analyzingId === item.id
                        ? "Analyzing…"
                        : itemAnalysis
                          ? "Re-analyze"
                          : "Analyze"}
                    </button>
                  </div>
                </div>
                <div className="border-t border-edge bg-surface-overlay/40 px-5 py-4">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-content-subtle">
                    SHA-256
                  </p>
                  <p className="mt-1 break-all font-mono text-[10px] leading-5 text-content-muted">
                    {item.sha256}
                  </p>
                </div>
                {/* silence unused index warning */}
                <span className="sr-only">{index}</span>
              </Panel>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* =========================================================
   ANALYSIS TAB
========================================================= */

function AnalysisTab({ analysis }: { analysis: PcapAnalysis | null }) {
  if (!analysis) {
    return (
      <Panel className="nfx-panel-enter">
        <EmptyState
          title="No PCAP analysis available"
          description="Select evidence and analyze the PCAP before opening this section."
        />
      </Panel>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        <MetricCard label="Packets" value={formatNumber(analysis.packet_count)} className="nfx-metric" />
        <MetricCard label="Hosts" value={formatNumber(analysis.host_count)} className="nfx-metric" />
        <MetricCard label="TCP" value={formatNumber(analysis.tcp_count)} className="nfx-metric" />
        <MetricCard label="UDP" value={formatNumber(analysis.udp_count)} className="nfx-metric" />
        <MetricCard label="ICMP" value={formatNumber(analysis.icmp_count)} className="nfx-metric" />
        <MetricCard label="Flows" value={formatNumber(analysis.flow_count)} className="nfx-metric" />
        <MetricCard label="DNS" value={formatNumber(analysis.dns_count)} className="nfx-metric" />
        <MetricCard label="HTTP" value={formatNumber(analysis.http_count)} className="nfx-metric" />
        <MetricCard label="HTTPS" value={formatNumber(analysis.https_count)} className="nfx-metric" />
        <MetricCard label="Duration" value={formatDuration(analysis.duration)} className="nfx-metric" />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel className="nfx-panel-enter nfx-panel-hover">
          <PanelHeader
            icon={<Clock3 className="h-5 w-5" />}
            title="Capture window"
            description="Original packet capture period"
          />
          <div className="space-y-5 p-6">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-content-subtle">
                Start
              </p>
              <p className="mt-1 text-sm text-content">
                {formatTimestamp(analysis.capture_start)}
              </p>
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-content-subtle">
                End
              </p>
              <p className="mt-1 text-sm text-content">
                {formatTimestamp(analysis.capture_end)}
              </p>
            </div>
          </div>
        </Panel>

        <Panel className="nfx-panel-enter nfx-panel-hover">
          <PanelHeader
            title="Analysis status"
            description="Backend processing record"
          />
          <div className="p-6">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-status-verified/10 text-status-verified">
                <Activity className="h-5 w-5" />
              </div>
              <div>
                <p className="text-sm font-medium capitalize text-content">
                  {analysis.status}
                </p>
                <p className="mt-1 text-xs text-content-subtle">
                  Analysis created{" "}
                  {new Date(analysis.created_at).toLocaleString()}
                </p>
              </div>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}

/* =========================================================
   HOSTS TAB
========================================================= */

function HostsTab({
  caseId,
  evidenceId,
  analysis,
}: {
  caseId: string;
  evidenceId: string;
  analysis: PcapAnalysis | null;
}) {
  const [hosts, setHosts] = useState<NetworkHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [discovering, setDiscovering] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const loadHosts = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getDiscoveredHosts(caseId, evidenceId);
      setHosts(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load hosts");
    } finally {
      setLoading(false);
    }
  }, [caseId, evidenceId]);

  const handleDiscover = useCallback(async () => {
    try {
      setDiscovering(true);
      setError(null);
      const data = await discoverHosts(caseId, evidenceId);
      setHosts(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to discover hosts");
    } finally {
      setDiscovering(false);
    }
  }, [caseId, evidenceId]);

  useEffect(() => {
    void loadHosts();
  }, [loadHosts]);

  const filteredHosts = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return hosts;
    return hosts.filter((host) =>
      [
        host.ip_address,
        String(host.unique_destinations),
        String(host.unique_sources),
      ]
        .join(" ")
        .toLowerCase()
        .includes(query)
    );
  }, [hosts, search]);

  const totalPackets = hosts.reduce(
    (sum, host) => sum + host.packets_sent + host.packets_received,
    0
  );
  const totalBytes = hosts.reduce(
    (sum, host) => sum + host.bytes_sent + host.bytes_received,
    0
  );
  const mostActive = hosts.length
    ? [...hosts].sort(
        (a, b) =>
          b.packets_sent +
          b.packets_received -
          (a.packets_sent + a.packets_received)
      )[0]
    : null;

  if (!analysis) {
    return (
      <Panel className="nfx-panel-enter">
        <EmptyState
          title="Analyze the PCAP first"
          description="Host discovery is built from the network flows generated during PCAP analysis."
        />
      </Panel>
    );
  }

  return (
    <div className="space-y-6">
      <Panel elevated className="nfx-panel-enter">
        <div className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-semibold text-content">
              Host discovery
            </h2>
            <p className="mt-1 text-sm text-content-muted">
              Hosts derived from communication flows in the selected PCAP.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void handleDiscover()}
            disabled={discovering}
            className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-xs font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${discovering ? "animate-spin" : ""}`}
            />
            {discovering
              ? "Discovering…"
              : hosts.length > 0
                ? "Refresh hosts"
                : "Discover hosts"}
          </button>
        </div>
      </Panel>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Hosts"
          value={formatNumber(hosts.length)}
          description={`Analysis reported ${analysis.host_count}`}
          icon={<Server className="h-4 w-4" />}
          className="nfx-metric"
        />
        <MetricCard
          label="Packets"
          value={formatNumber(totalPackets)}
          description="Sent + received"
          className="nfx-metric"
        />
        <MetricCard
          label="Traffic"
          value={formatBytes(totalBytes)}
          description="Sent + received"
          className="nfx-metric"
        />
        <MetricCard
          label="Most active"
          value={mostActive ? mostActive.ip_address : "—"}
          description={
            mostActive
              ? `${formatNumber(
                  mostActive.packets_sent + mostActive.packets_received
                )} packets`
              : "No data"
          }
          className="nfx-metric"
        />
      </div>

      <Panel className="nfx-panel-enter">
        <PanelHeader
          title="Discovered hosts"
          description={`${filteredHosts.length} shown`}
          actions={
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-content-subtle" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search IP…"
                className="h-9 w-full rounded-lg border border-edge bg-surface-subtle pl-9 pr-3 text-xs text-content outline-none placeholder:text-content-subtle focus:border-accent sm:w-60"
              />
            </div>
          }
        />
        {loading ? (
          <LoadingState label="Loading hosts…" />
        ) : error ? (
          <ErrorState description={error} onRetry={() => void loadHosts()} />
        ) : filteredHosts.length === 0 ? (
          <EmptyState
            title="No hosts found"
            description="Run host discovery or adjust your search."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1000px] text-left text-sm">
              <thead className="border-b border-edge bg-surface-overlay/40 text-[10px] uppercase tracking-wider text-content-subtle">
                <tr>
                  {[
                    "IP address",
                    "Packets sent",
                    "Packets received",
                    "Bytes sent",
                    "Bytes received",
                    "Destinations",
                    "Sources",
                    "First seen",
                    "Last seen",
                  ].map((h) => (
                    <th key={h} className="px-5 py-3 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {filteredHosts.map((host) => (
                  <tr key={host.id} className="nfx-table-row">
                    <td className="px-5 py-4 font-mono text-xs font-medium text-content">
                      {host.ip_address}
                    </td>
                    <td className="px-5 py-4 text-xs tabular-nums text-content-muted">
                      {formatNumber(host.packets_sent)}
                    </td>
                    <td className="px-5 py-4 text-xs tabular-nums text-content-muted">
                      {formatNumber(host.packets_received)}
                    </td>
                    <td className="px-5 py-4 text-xs tabular-nums text-content-muted">
                      {formatBytes(host.bytes_sent)}
                    </td>
                    <td className="px-5 py-4 text-xs tabular-nums text-content-muted">
                      {formatBytes(host.bytes_received)}
                    </td>
                    <td className="px-5 py-4 text-xs tabular-nums text-content-muted">
                      {host.unique_destinations}
                    </td>
                    <td className="px-5 py-4 text-xs tabular-nums text-content-muted">
                      {host.unique_sources}
                    </td>
                    <td className="whitespace-nowrap px-5 py-4 text-[11px] text-content-subtle">
                      {formatTimestamp(host.first_seen)}
                    </td>
                    <td className="whitespace-nowrap px-5 py-4 text-[11px] text-content-subtle">
                      {formatTimestamp(host.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

/* =========================================================
   FLOWS TAB
========================================================= */

function FlowsTab({
  caseId,
  evidenceId,
  analysis,
}: {
  caseId: string;
  evidenceId: string;
  analysis: PcapAnalysis | null;
}) {
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [protocol, setProtocol] = useState("ALL");
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const pageSize = 25;

  const loadFlows = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getEvidenceFlows(caseId, evidenceId, {
        limit: pageSize,
        offset: page * pageSize,
        protocol,
      });
      setFlows(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load flows");
    } finally {
      setLoading(false);
    }
  }, [caseId, evidenceId, page, protocol]);

  useEffect(() => {
    void loadFlows();
  }, [loadFlows]);

  if (!analysis) {
    return (
      <Panel className="nfx-panel-enter">
        <EmptyState
          title="Analyze the PCAP first"
          description="Network flows are generated during PCAP analysis."
        />
      </Panel>
    );
  }

  return (
    <div className="space-y-6">
      <Panel elevated className="nfx-panel-enter">
        <div className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-semibold text-content">
              Network flows
            </h2>
            <p className="mt-1 text-sm text-content-muted">
              Aggregated source-to-destination communication.
            </p>
          </div>
          <div className="relative">
            <select
              value={protocol}
              onChange={(e) => {
                setProtocol(e.target.value);
                setPage(0);
              }}
              className="h-9 appearance-none rounded-lg border border-edge bg-surface-subtle pl-3 pr-9 text-xs font-medium text-content outline-none focus:border-accent"
            >
              <option value="ALL">All protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="OTHER">Other</option>
            </select>
            <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-content-subtle" />
          </div>
        </div>
      </Panel>

      <Panel className="nfx-panel-enter">
        {loading ? (
          <LoadingState label="Loading network flows…" />
        ) : error ? (
          <ErrorState description={error} onRetry={() => void loadFlows()} />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1000px] text-left text-sm">
                <thead className="border-b border-edge bg-surface-overlay/40 text-[10px] uppercase tracking-wider text-content-subtle">
                  <tr>
                    {[
                      "Source",
                      "Destination",
                      "Protocol",
                      "Ports",
                      "Packets",
                      "Bytes",
                      "First seen",
                      "Last seen",
                    ].map((h) => (
                      <th key={h} className="px-5 py-3 font-medium">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge">
                  {flows.map((flow) => (
                    <tr key={flow.id} className="nfx-table-row">
                      <td className="px-5 py-4 font-mono text-xs text-content">
                        {flow.source_ip}
                      </td>
                      <td className="px-5 py-4 font-mono text-xs text-content">
                        {flow.destination_ip}
                      </td>
                      <td className="px-5 py-4">
                        <span className="rounded-md border border-edge bg-surface-overlay px-2 py-1 text-[10px] font-semibold text-content-muted">
                          {flow.protocol}
                        </span>
                      </td>
                      <td className="px-5 py-4 font-mono text-[11px] text-content-subtle">
                        {flow.source_port ?? "—"} → {flow.destination_port ?? "—"}
                      </td>
                      <td className="px-5 py-4 text-xs tabular-nums text-content-muted">
                        {formatNumber(flow.packets)}
                      </td>
                      <td className="px-5 py-4 text-xs tabular-nums text-content-muted">
                        {formatBytes(flow.bytes)}
                      </td>
                      <td className="whitespace-nowrap px-5 py-4 text-[11px] text-content-subtle">
                        {formatTimestamp(flow.first_seen)}
                      </td>
                      <td className="whitespace-nowrap px-5 py-4 text-[11px] text-content-subtle">
                        {formatTimestamp(flow.last_seen)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-edge px-5 py-4">
              <p className="text-xs text-content-subtle">
                Page {page + 1} · {flows.length} flows shown
              </p>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={page === 0 || loading}
                  onClick={() => setPage((v) => Math.max(0, v - 1))}
                  className="inline-flex h-8 items-center gap-1 rounded-lg border border-edge bg-surface-subtle px-3 text-xs font-medium text-content-muted transition hover:border-edge-strong hover:text-content disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                  Previous
                </button>
                <button
                  type="button"
                  disabled={flows.length < pageSize || loading}
                  onClick={() => setPage((v) => v + 1)}
                  className="inline-flex h-8 items-center gap-1 rounded-lg border border-edge bg-surface-subtle px-3 text-xs font-medium text-content-muted transition hover:border-edge-strong hover:text-content disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Next
                  <ChevronLeft className="h-3.5 w-3.5 rotate-180" />
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}

/* =========================================================
   PROTOCOLS TAB
========================================================= */

function ProtocolsTab({
  caseId,
  evidenceId,
  analysis,
  dnsRecords,
  httpTransactions,
  tlsSessions,
  setDnsRecords,
  setHttpTransactions,
  setTlsSessions,
}: {
  caseId: string;
  evidenceId: string;
  analysis: PcapAnalysis | null;
  dnsRecords: DNSRecord[];
  httpTransactions: HTTPTransaction[];
  tlsSessions: TLSSession[];
  setDnsRecords: (value: DNSRecord[]) => void;
  setHttpTransactions: (value: HTTPTransaction[]) => void;
  setTlsSessions: (value: TLSSession[]) => void;
}) {
  const [protocolTab, setProtocolTab] = useState<ProtocolTab>("dns");
  const [search, setSearch] = useState("");
  const [analyzingDNS, setAnalyzingDNS] = useState(false);
  const [analyzingHTTP, setAnalyzingHTTP] = useState(false);
  const [analyzingTLS, setAnalyzingTLS] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadDNS = useCallback(async () => {
    try {
      const result = await getDNSRecords(caseId, evidenceId, {
        limit: 500,
        offset: 0,
      });
      setDnsRecords(result);
    } catch (err) {
      console.error(err);
    }
  }, [caseId, evidenceId, setDnsRecords]);

  const loadHTTP = useCallback(async () => {
    try {
      const result = await getHTTPTransactions(caseId, evidenceId, {
        limit: 500,
        offset: 0,
      });
      setHttpTransactions(result);
    } catch (err) {
      console.error(err);
    }
  }, [caseId, evidenceId, setHttpTransactions]);

  const loadTLS = useCallback(async () => {
    try {
      const result = await getTLSSessions(caseId, evidenceId, {
        limit: 500,
        offset: 0,
      });
      setTlsSessions(result);
    } catch (err) {
      console.error(err);
    }
  }, [caseId, evidenceId, setTlsSessions]);

  useEffect(() => {
    if (protocolTab === "dns" && dnsRecords.length === 0) void loadDNS();
    if (protocolTab === "http" && httpTransactions.length === 0) void loadHTTP();
    if (protocolTab === "tls" && tlsSessions.length === 0) void loadTLS();
  }, [
    protocolTab,
    dnsRecords.length,
    httpTransactions.length,
    tlsSessions.length,
    loadDNS,
    loadHTTP,
    loadTLS,
  ]);

  const handleAnalyzeDNS = useCallback(async () => {
    try {
      setAnalyzingDNS(true);
      setError(null);
      const result = await analyzeDNS(caseId, evidenceId);
      setDnsRecords(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "DNS analysis failed");
    } finally {
      setAnalyzingDNS(false);
    }
  }, [caseId, evidenceId, setDnsRecords]);

  const handleAnalyzeHTTP = useCallback(async () => {
    try {
      setAnalyzingHTTP(true);
      setError(null);
      const result = await analyzeHTTP(caseId, evidenceId);
      setHttpTransactions(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "HTTP analysis failed");
    } finally {
      setAnalyzingHTTP(false);
    }
  }, [caseId, evidenceId, setHttpTransactions]);

  const handleAnalyzeTLS = useCallback(async () => {
    try {
      setAnalyzingTLS(true);
      setError(null);
      const result = await analyzeTLS(caseId, evidenceId);
      setTlsSessions(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "TLS analysis failed");
    } finally {
      setAnalyzingTLS(false);
    }
  }, [caseId, evidenceId, setTlsSessions]);

  const filteredDNS = useMemo(() => {
    const v = search.trim().toLowerCase();
    if (!v) return dnsRecords;
    return dnsRecords.filter((r) =>
      [
        r.source_ip,
        r.destination_ip,
        r.query_name,
        r.query_type,
        String(r.response_code ?? ""),
        r.answers,
      ]
        .join(" ")
        .toLowerCase()
        .includes(v)
    );
  }, [dnsRecords, search]);

  const filteredHTTP = useMemo(() => {
    const v = search.trim().toLowerCase();
    if (!v) return httpTransactions;
    return httpTransactions.filter((t) =>
      [
        t.source_ip,
        t.destination_ip,
        t.method,
        t.host,
        t.uri,
        String(t.status_code ?? ""),
        t.user_agent,
      ]
        .join(" ")
        .toLowerCase()
        .includes(v)
    );
  }, [httpTransactions, search]);

  const filteredTLS = useMemo(() => {
    const v = search.trim().toLowerCase();
    if (!v) return tlsSessions;
    return tlsSessions.filter((t) =>
      [
        t.source_ip,
        t.destination_ip,
        t.tls_version,
        t.sni,
        t.cipher,
        t.handshake_type,
      ]
        .join(" ")
        .toLowerCase()
        .includes(v)
    );
  }, [tlsSessions, search]);

  if (!analysis) {
    return (
      <Panel className="nfx-panel-enter">
        <EmptyState
          title="Analyze the PCAP first"
          description="Protocol analysis is built from the PCAP. Run analysis before exploring DNS, HTTP, and TLS."
        />
      </Panel>
    );
  }

  return (
    <div className="space-y-5">
      {error && (
        <div
          role="alert"
          className="nfx-panel-enter rounded-lg border border-severity-critical/30 bg-severity-critical/10 px-4 py-3 text-xs text-severity-critical"
        >
          {error}
        </div>
      )}

      <Panel className="nfx-panel-enter">
        <div className="flex overflow-x-auto border-b border-edge">
          {(
            [
              ["dns", "DNS", Globe],
              ["http", "HTTP", Activity],
              ["tls", "TLS", Lock],
            ] as [ProtocolTab, string, React.ElementType][]
          ).map(([tab, label, IconCmp]) => {
            const active = protocolTab === tab;
            return (
              <button
                key={tab}
                onClick={() => setProtocolTab(tab)}
                className={[
                  "relative flex min-w-[120px] items-center justify-center gap-2 px-5 py-4 text-sm font-medium transition",
                  active
                    ? "text-content"
                    : "text-content-subtle hover:text-content",
                ].join(" ")}
              >
                <IconCmp className="h-4 w-4" />
                {label}
                {active && (
                  <span
                    aria-hidden
                    className="absolute inset-x-4 bottom-0 h-[2px] rounded-full bg-accent"
                  />
                )}
              </button>
            );
          })}
        </div>

        {/* DNS */}
        {protocolTab === "dns" && (
          <div className="p-5">
            <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-sm font-semibold text-content">
                    DNS analysis
                  </h2>
                  <StatusBadge
                    value={`${dnsRecords.length} records`}
                    tone="neutral"
                  />
                </div>
                <p className="mt-1 text-xs text-content-subtle">
                  DNS queries and responses extracted from the network capture.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-content-subtle" />
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search DNS…"
                    className="h-9 w-52 rounded-lg border border-edge bg-surface-subtle pl-9 pr-3 text-xs text-content outline-none placeholder:text-content-subtle focus:border-accent"
                  />
                </div>
                <button
                  onClick={() => void handleAnalyzeDNS()}
                  disabled={analyzingDNS}
                  className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-xs font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5" />
                  {analyzingDNS ? "Analyzing…" : "Analyze DNS"}
                </button>
              </div>
            </div>

            <div className="mb-5 grid gap-3 sm:grid-cols-3">
              <MetricCard label="Records" value={dnsRecords.length} className="nfx-metric" />
              <MetricCard label="DNS count" value={analysis.dns_count} className="nfx-metric" />
              <MetricCard
                label="Unique queries"
                value={new Set(dnsRecords.map((r) => r.query_name)).size}
                className="nfx-metric"
              />
            </div>

            {filteredDNS.length === 0 ? (
              <EmptyState
                title="No DNS records loaded"
                description="Run DNS analysis to extract queries and responses."
              />
            ) : (
              <div className="overflow-x-auto rounded-lg border border-edge">
                <table className="w-full min-w-[950px] text-left text-xs">
                  <thead className="border-b border-edge bg-surface-overlay/40 text-[10px] uppercase tracking-wider text-content-subtle">
                    <tr>
                      {[
                        "Time",
                        "Source",
                        "DNS server",
                        "Query",
                        "Type",
                        "RCODE",
                        "Answers",
                      ].map((h) => (
                        <th key={h} className="px-4 py-3 font-medium">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-edge">
                    {filteredDNS.map((record) => (
                      <tr key={record.id} className="nfx-table-row">
                        <td className="whitespace-nowrap px-4 py-3 text-content-subtle">
                          {formatTimestamp(record.timestamp)}
                        </td>
                        <td className="px-4 py-3 font-mono text-content">
                          {record.source_ip}
                        </td>
                        <td className="px-4 py-3 font-mono text-content">
                          {record.destination_ip}
                        </td>
                        <td
                          title={record.query_name}
                          className="max-w-[280px] truncate px-4 py-3 font-mono font-medium text-content"
                        >
                          {record.query_name}
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge
                            value={record.query_type ?? "—"}
                            tone="neutral"
                          />
                        </td>
                        <td className="px-4 py-3 text-content-muted tabular-nums">
                          {record.response_code ?? "—"}
                        </td>
                        <td
                          title={record.answers ?? undefined}
                          className="max-w-[300px] truncate px-4 py-3 text-content-subtle"
                        >
                          {record.answers ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* HTTP */}
        {protocolTab === "http" && (
          <div className="p-5">
            <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-sm font-semibold text-content">
                    HTTP analysis
                  </h2>
                  <StatusBadge
                    value={`${httpTransactions.length} transactions`}
                    tone="neutral"
                  />
                </div>
                <p className="mt-1 text-xs text-content-subtle">
                  HTTP requests and responses extracted from the capture.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-content-subtle" />
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search HTTP…"
                    className="h-9 w-52 rounded-lg border border-edge bg-surface-subtle pl-9 pr-3 text-xs text-content outline-none placeholder:text-content-subtle focus:border-accent"
                  />
                </div>
                <button
                  onClick={() => void handleAnalyzeHTTP()}
                  disabled={analyzingHTTP}
                  className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-xs font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5" />
                  {analyzingHTTP ? "Analyzing…" : "Analyze HTTP"}
                </button>
              </div>
            </div>

            <div className="mb-5 grid gap-3 sm:grid-cols-3">
              <MetricCard label="Transactions" value={httpTransactions.length} className="nfx-metric" />
              <MetricCard label="HTTP count" value={analysis.http_count} className="nfx-metric" />
              <MetricCard
                label="Unique hosts"
                value={
                  new Set(
                    httpTransactions.map((t) => t.host).filter(Boolean)
                  ).size
                }
                className="nfx-metric"
              />
            </div>

            {filteredHTTP.length === 0 ? (
              <EmptyState
                title="No HTTP transactions loaded"
                description="Run HTTP analysis to extract requests and responses."
              />
            ) : (
              <div className="overflow-x-auto rounded-lg border border-edge">
                <table className="w-full min-w-[1150px] text-left text-xs">
                  <thead className="border-b border-edge bg-surface-overlay/40 text-[10px] uppercase tracking-wider text-content-subtle">
                    <tr>
                      {[
                        "Time",
                        "Source",
                        "Destination",
                        "Method",
                        "Host",
                        "URI",
                        "Status",
                        "User agent",
                      ].map((h) => (
                        <th key={h} className="px-4 py-3 font-medium">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-edge">
                    {filteredHTTP.map((t) => (
                      <tr key={t.id} className="nfx-table-row">
                        <td className="whitespace-nowrap px-4 py-3 text-content-subtle">
                          {formatTimestamp(t.timestamp)}
                        </td>
                        <td className="px-4 py-3 font-mono text-content">
                          {t.source_ip}
                          {t.source_port ? `:${t.source_port}` : ""}
                        </td>
                        <td className="px-4 py-3 font-mono text-content">
                          {t.destination_ip}
                          {t.destination_port ? `:${t.destination_port}` : ""}
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge value={t.method ?? "—"} tone="neutral" />
                        </td>
                        <td
                          title={t.host ?? undefined}
                          className="max-w-[220px] truncate px-4 py-3 font-medium text-content"
                        >
                          {t.host ?? "—"}
                        </td>
                        <td
                          title={t.uri ?? undefined}
                          className="max-w-[280px] truncate px-4 py-3 font-mono text-content-subtle"
                        >
                          {t.uri ?? "—"}
                        </td>
                        <td className="px-4 py-3 tabular-nums text-content-muted">
                          {t.status_code ?? "—"}
                        </td>
                        <td
                          title={t.user_agent ?? undefined}
                          className="max-w-[280px] truncate px-4 py-3 text-content-subtle"
                        >
                          {t.user_agent ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* TLS */}
        {protocolTab === "tls" && (
          <div className="p-5">
            <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-sm font-semibold text-content">
                    TLS analysis
                  </h2>
                  <StatusBadge
                    value={`${tlsSessions.length} sessions`}
                    tone="neutral"
                  />
                </div>
                <p className="mt-1 text-xs text-content-subtle">
                  TLS handshake metadata such as version, SNI, and cipher.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-content-subtle" />
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search TLS…"
                    className="h-9 w-52 rounded-lg border border-edge bg-surface-subtle pl-9 pr-3 text-xs text-content outline-none placeholder:text-content-subtle focus:border-accent"
                  />
                </div>
                <button
                  onClick={() => void handleAnalyzeTLS()}
                  disabled={analyzingTLS}
                  className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-xs font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5" />
                  {analyzingTLS ? "Analyzing…" : "Analyze TLS"}
                </button>
              </div>
            </div>

            <div className="mb-5 grid gap-3 sm:grid-cols-3">
              <MetricCard label="TLS sessions" value={tlsSessions.length} className="nfx-metric" />
              <MetricCard label="HTTPS packets" value={analysis.https_count} className="nfx-metric" />
              <MetricCard
                label="Unique SNI"
                value={
                  new Set(tlsSessions.map((t) => t.sni).filter(Boolean)).size
                }
                className="nfx-metric"
              />
            </div>

            {filteredTLS.length === 0 ? (
              <EmptyState
                title="No TLS sessions loaded"
                description="Run TLS analysis to extract available handshake metadata."
              />
            ) : (
              <div className="overflow-x-auto rounded-lg border border-edge">
                <table className="w-full min-w-[1100px] text-left text-xs">
                  <thead className="border-b border-edge bg-surface-overlay/40 text-[10px] uppercase tracking-wider text-content-subtle">
                    <tr>
                      {[
                        "Time",
                        "Source",
                        "Destination",
                        "TLS version",
                        "SNI",
                        "Cipher",
                        "Handshake",
                      ].map((h) => (
                        <th key={h} className="px-4 py-3 font-medium">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-edge">
                    {filteredTLS.map((t) => (
                      <tr key={t.id} className="nfx-table-row">
                        <td className="whitespace-nowrap px-4 py-3 text-content-subtle">
                          {formatTimestamp(t.timestamp)}
                        </td>
                        <td className="px-4 py-3 font-mono text-content">
                          {t.source_ip}
                          {t.source_port ? `:${t.source_port}` : ""}
                        </td>
                        <td className="px-4 py-3 font-mono text-content">
                          {t.destination_ip}
                          {t.destination_port ? `:${t.destination_port}` : ""}
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge
                            value={t.tls_version ?? "Unknown"}
                            tone="neutral"
                          />
                        </td>
                        <td
                          title={t.sni ?? undefined}
                          className="max-w-[250px] truncate px-4 py-3 font-medium text-content"
                        >
                          {t.sni ?? "—"}
                        </td>
                        <td
                          title={t.cipher ?? undefined}
                          className="max-w-[280px] truncate px-4 py-3 font-mono text-content-subtle"
                        >
                          {t.cipher ?? "—"}
                        </td>
                        <td className="px-4 py-3 text-content-muted">
                          {t.handshake_type ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="mt-4 rounded-lg border border-edge bg-surface-overlay/40 px-4 py-3 text-xs leading-5 text-content-muted">
              TLS analysis displays available handshake metadata from the PCAP.
              It does not decrypt or expose encrypted application payloads.
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

/* =========================================================
   TOPOLOGY
========================================================= */

function classifyNodeZone(node: NetworkTopology["nodes"][number]): TopologyZone {
  return classifyNode(node);
}

function getCurvePath(
  source: TopologyPosition,
  target: TopologyPosition
): string {
  const distance = Math.abs(target.x - source.x);
  const controlOffset = Math.max(80, distance * 0.38);
  const direction = target.x >= source.x ? 1 : -1;
  const c1x = source.x + controlOffset * direction;
  const c2x = target.x - controlOffset * direction;
  return `M ${source.x} ${source.y} C ${c1x} ${source.y} ${c2x} ${target.y} ${target.x} ${target.y}`;
}

function TopologyTab({
  caseId,
  evidenceId,
  analysis,
}: {
  caseId: string;
  evidenceId: string;
  analysis: PcapAnalysis | null;
}) {
  const [topology, setTopology] = useState<NetworkTopology | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const loadTopology = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getNetworkTopology(caseId, evidenceId);
      setTopology(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load topology");
    } finally {
      setLoading(false);
    }
  }, [caseId, evidenceId]);

  useEffect(() => {
    void loadTopology();
  }, [loadTopology]);

  if (!analysis) {
    return (
      <Panel className="nfx-panel-enter">
        <EmptyState
          title="Analyze the PCAP first"
          description="The network topology is generated from analyzed network flows."
        />
      </Panel>
    );
  }

  if (loading) {
    return (
      <Panel className="nfx-panel-enter">
        <LoadingState label="Loading network topology…" />
      </Panel>
    );
  }

  if (error) {
    return (
      <Panel className="nfx-panel-enter">
        <ErrorState
          title="Unable to load topology"
          description={error}
          onRetry={() => void loadTopology()}
        />
      </Panel>
    );
  }

  if (!topology) {
    return (
      <Panel className="nfx-panel-enter">
        <EmptyState
          title="No topology available"
          description="No communication topology was generated for this evidence."
        />
      </Panel>
    );
  }

  const NODE_MIN_R = 8;
  const NODE_MAX_R = 16;
  const ZONE_TOP = 130;
  const ZONE_BOTTOM_PAD = 90;
  const MAX_NODES_PER_ZONE = 14;
  const MAX_EDGES_DRAWN = 40;
  const LABEL_W = 138;
  const LABEL_H = 18;
  const LABEL_GAP = 6;

  const query = search.trim().toLowerCase();
  const searchMatches = query
    ? topology.nodes.filter(
        (n) =>
          n.id.toLowerCase().includes(query) ||
          n.label.toLowerCase().includes(query)
      )
    : [];
  const searchMatchIds = new Set(searchMatches.map((n) => n.id));

  const byZone: Record<TopologyZone, NetworkTopology["nodes"]> = {
    internal: [],
    infrastructure: [],
    external: [],
  };

  const sortedNodes = [...topology.nodes].sort((a, b) => b.bytes - a.bytes);

  for (const n of sortedNodes) {
    const zone = classifyNodeZone(n);
    const withinCap = byZone[zone].length < MAX_NODES_PER_ZONE;
    const matchesSearch = searchMatchIds.has(n.id);
    if (withinCap || matchesSearch) byZone[zone].push(n);
  }

  const activeZones = (
    ["internal", "infrastructure", "external"] as TopologyZone[]
  ).filter((z) => byZone[z].length > 0);

  const viewWidth = 1180;
  const viewHeight = Math.max(
    560,
    ZONE_TOP + ZONE_BOTTOM_PAD + MAX_NODES_PER_ZONE * 34
  );

  const columnX: Record<TopologyZone, number> = {
    internal: 0,
    infrastructure: 0,
    external: 0,
  };

  const columnCount = Math.max(1, activeZones.length);
  const columnSpacing =
    columnCount === 1 ? 0 : (viewWidth - 240) / (columnCount - 1);

  activeZones.forEach((zone, index) => {
    columnX[zone] =
      columnCount === 1 ? viewWidth / 2 : 120 + index * columnSpacing;
  });

  const positions = new Map<string, TopologyPosition>();
  for (const zone of activeZones) {
    const list = byZone[zone];
    const usable = viewHeight - ZONE_TOP - ZONE_BOTTOM_PAD;
    list.forEach((node, index) => {
      const y =
        list.length === 1
          ? ZONE_TOP + usable / 2
          : ZONE_TOP + (usable * index) / (list.length - 1);
      positions.set(node.id, { x: columnX[zone], y });
    });
  }

  const visibleNodeIds = new Set(
    activeZones.flatMap((z) => byZone[z].map((n) => n.id))
  );

  const candidateEdges = topology.edges
    .filter((e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target))
    .sort((a, b) => b.bytes - a.bytes);

  const visibleEdges = candidateEdges.slice(0, MAX_EDGES_DRAWN);
  const hiddenEdgeCount = candidateEdges.length - visibleEdges.length;

  const totalDrawnNodes = activeZones.reduce(
    (sum, z) => sum + byZone[z].length,
    0
  );
  const hiddenNodeCount = topology.node_count - totalDrawnNodes;

  const maxNodeBytes = Math.max(
    ...activeZones.flatMap((z) => byZone[z].map((n) => n.bytes)),
    1
  );
  const maxEdgeBytes = Math.max(...visibleEdges.map((e) => e.bytes), 1);

  const zoneTitle: Record<TopologyZone, string> = {
    internal: "INTERNAL NETWORK",
    infrastructure: "INFRASTRUCTURE / DNS",
    external: "EXTERNAL NETWORK",
  };
  const zoneSubtitle: Record<TopologyZone, string> = {
    internal: "Private / local systems",
    infrastructure: "DNS and infrastructure",
    external: "Public / Internet systems",
  };
  const zoneAccent: Record<TopologyZone, string> = {
    internal: "var(--color-accent)",
    infrastructure: "var(--color-atmos-violet)",
    external: "var(--color-atmos-amber)",
  };

  const internalCount = byZone.internal.length;
  const infrastructureCount = byZone.infrastructure.length;
  const externalCount = byZone.external.length;

  const selectedNodeData = selectedNode
    ? topology.nodes.find((n) => n.id === selectedNode) ?? null
    : null;

  const selectedEdges = selectedNode
    ? visibleEdges.filter(
        (e) => e.source === selectedNode || e.target === selectedNode
      )
    : [];

  const toggleNode = (id: string) =>
    setSelectedNode((cur) => (cur === id ? null : id));

  return (
    <div className="space-y-6">
      <Panel elevated className="nfx-panel-enter nfx-panel-hover">
        <div className="flex flex-col gap-5 p-6 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent text-accent-foreground">
                <Share2 className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-base font-semibold text-content">
                  Network communication map
                </h2>
                <p className="mt-1 text-sm text-content-muted">
                  Directional communication between observed systems.
                </p>
              </div>
            </div>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-content-subtle" />
              <input
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setSelectedNode(null);
                }}
                placeholder="Search IP or host…"
                className="h-9 w-full rounded-lg border border-edge bg-surface-subtle pl-9 pr-3 text-xs text-content outline-none placeholder:text-content-subtle focus:border-accent sm:w-64"
              />
            </div>
            <button
              type="button"
              onClick={() => void loadTopology()}
              className="inline-flex h-9 items-center justify-center gap-2 rounded-lg border border-edge bg-surface-subtle px-3 text-xs font-medium text-content-muted transition hover:border-edge-strong hover:text-content"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        </div>
      </Panel>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard
          label="Total nodes"
          value={formatNumber(topology.node_count)}
          description={`${totalDrawnNodes} shown`}
          className="nfx-metric"
        />
        <MetricCard
          label="Connections"
          value={formatNumber(topology.edge_count)}
          description={`${visibleEdges.length} drawn`}
          className="nfx-metric"
        />
        <MetricCard label="Internal" value={internalCount} className="nfx-metric" />
        <MetricCard label="Infrastructure" value={infrastructureCount} className="nfx-metric" />
        <MetricCard label="External" value={externalCount} className="nfx-metric" />
      </div>

      <Panel className="nfx-panel-enter">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3 border-b border-edge px-5 py-4">
          <div className="flex items-center gap-2">
            <span
              className="h-3.5 w-3.5 rounded-full border-2"
              style={{
                borderColor: "var(--color-accent)",
                background:
                  "color-mix(in oklab, var(--color-accent) 20%, transparent)",
              }}
            />
            <span className="text-xs font-medium text-content-muted">
              Internal host
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className="h-3.5 w-3.5 rounded-full border-2"
              style={{
                borderColor: "var(--color-atmos-violet)",
                background:
                  "color-mix(in oklab, var(--color-atmos-violet) 20%, transparent)",
              }}
            />
            <span className="text-xs font-medium text-content-muted">
              DNS / infrastructure
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className="h-3.5 w-3.5 rounded-full border-2"
              style={{
                borderColor: "var(--color-atmos-amber)",
                background:
                  "color-mix(in oklab, var(--color-atmos-amber) 20%, transparent)",
              }}
            />
            <span className="text-xs font-medium text-content-muted">
              External host
            </span>
          </div>
          <div className="ml-auto flex items-center gap-2 text-[11px] text-content-subtle">
            <span>Larger node = more traffic</span>
          </div>
        </div>

        <div className="overflow-x-auto bg-surface-overlay/40">
          <svg
            viewBox={`0 0 ${viewWidth} ${viewHeight}`}
            className="w-full"
            style={{ minWidth: 900, maxHeight: 720 }}
          >
            <defs>
              <marker
                id="nfx-arrow"
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path
                  d="M 0 0 L 10 5 L 0 10 z"
                  fill="var(--color-content-subtle)"
                />
              </marker>
            </defs>

            {activeZones.map((zone) => {
              const yTop = ZONE_TOP - 60;
              const yBottom = viewHeight - 30;
              const frameX = columnX[zone] - 190;
              return (
                <g key={zone}>
                  <rect
                    x={frameX}
                    y={yTop}
                    width={380}
                    height={yBottom - yTop}
                    rx={20}
                    fill="color-mix(in oklab, var(--color-surface-raised) 55%, transparent)"
                    stroke="var(--color-edge)"
                  />
                  <text
                    x={columnX[zone]}
                    y={yTop + 30}
                    textAnchor="middle"
                    fill={zoneAccent[zone]}
                    className="text-[12px] font-semibold tracking-wider"
                  >
                    {zoneTitle[zone]}
                  </text>
                  <text
                    x={columnX[zone]}
                    y={yTop + 48}
                    textAnchor="middle"
                    fill="var(--color-content-subtle)"
                    className="text-[10px]"
                  >
                    {zoneSubtitle[zone]}
                  </text>
                </g>
              );
            })}

            {visibleEdges.map((edge) => {
              const source = positions.get(edge.source);
              const target = positions.get(edge.target);
              if (!source || !target) return null;

              const isSelected =
                selectedNode !== null &&
                (edge.source === selectedNode ||
                  edge.target === selectedNode);
              const isDimmed = selectedNode !== null && !isSelected;

              const strokeWidth =
                1 + Math.min(3.5, (edge.bytes / maxEdgeBytes) * 3.5);
              const path = getCurvePath(source, target);

              const midX = (source.x + target.x) / 2;
              const midY = (source.y + target.y) / 2;

              return (
                <g key={edge.id} opacity={isDimmed ? 0.08 : 1}>
                  <path
                    d={path}
                    fill="none"
                    stroke={
                      isSelected
                        ? "var(--color-accent)"
                        : "color-mix(in oklab, var(--color-edge-strong) 70%, transparent)"
                    }
                    strokeWidth={isSelected ? strokeWidth + 1 : strokeWidth}
                    strokeLinecap="round"
                    markerEnd="url(#nfx-arrow)"
                  />
                  {isSelected && (
                    <g transform={`translate(${midX}, ${midY})`}>
                      <rect
                        x={-60}
                        y={-14}
                        width={120}
                        height={26}
                        rx={7}
                        fill="var(--color-surface-raised)"
                        stroke="var(--color-edge)"
                      />
                      <text
                        x={0}
                        y={-2}
                        textAnchor="middle"
                        fill="var(--color-content)"
                        className="text-[9px] font-semibold"
                      >
                        {edge.protocol}
                        {edge.destination_port
                          ? `:${edge.destination_port}`
                          : ""}
                      </text>
                      <text
                        x={0}
                        y={9}
                        textAnchor="middle"
                        fill="var(--color-content-subtle)"
                        className="text-[8px]"
                      >
                        {formatBytes(edge.bytes)} ·{" "}
                        {formatNumber(edge.packets)} pkts
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {activeZones
              .flatMap((zone) => byZone[zone].map((node) => ({ node, zone })))
              .map(({ node, zone }) => {
                const pos = positions.get(node.id);
                if (!pos) return null;

                const selected = selectedNode === node.id;

                const isNeighbor =
                  selectedNode !== null &&
                  visibleEdges.some(
                    (e) =>
                      (e.source === selectedNode && e.target === node.id) ||
                      (e.target === selectedNode && e.source === node.id)
                  );
                const dimmed = selectedNode !== null && !selected && !isNeighbor;

                const trafficRatio = node.bytes / maxNodeBytes;
                const radius =
                  NODE_MIN_R + trafficRatio * (NODE_MAX_R - NODE_MIN_R);

                const zoneColor = zoneAccent[zone];
                const zoneFill = `color-mix(in oklab, ${zoneColor} 20%, var(--color-surface-raised))`;

                const isRightColumn = zone === "external";
                const labelX = isRightColumn
                  ? pos.x - LABEL_GAP - LABEL_W
                  : pos.x + radius + LABEL_GAP;
                const labelY = pos.y - LABEL_H / 2;

                const displayLabel =
                  node.label.length > 18
                    ? `${node.label.slice(0, 16)}…`
                    : node.label;

                return (
                  <g
                    key={node.id}
                    role="button"
                    tabIndex={0}
                    aria-label={`${node.label}. ${formatBytes(
                      node.bytes
                    )}, ${formatNumber(node.packets)} packets.`}
                    aria-pressed={selected}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        toggleNode(node.id);
                      }
                    }}
                    onClick={() => toggleNode(node.id)}
                    className={`cursor-pointer focus:outline-none ${
                      dimmed ? "opacity-25" : "opacity-100"
                    }`}
                  >
                    {selected && (
                      <circle
                        cx={pos.x}
                        cy={pos.y}
                        r={radius + 6}
                        fill={zoneColor}
                        opacity={0.18}
                      />
                    )}

                    <circle
                      cx={pos.x}
                      cy={pos.y}
                      r={radius}
                      fill={zoneFill}
                      stroke={zoneColor}
                      strokeWidth={selected ? 2.5 : 1.5}
                    />

                    <g transform={`translate(${labelX}, ${labelY})`}>
                      <rect
                        width={LABEL_W}
                        height={LABEL_H}
                        rx={4}
                        fill="color-mix(in oklab, var(--color-surface-raised) 92%, transparent)"
                        stroke={selected ? zoneColor : "var(--color-edge)"}
                      />
                      <text
                        x={6}
                        y={12}
                        fill="var(--color-content)"
                        className="text-[9px] font-medium"
                      >
                        {displayLabel}
                      </text>
                    </g>

                    {selected && (
                      <g
                        transform={`translate(${
                          isRightColumn ? pos.x - 220 : pos.x + 20
                        }, ${pos.y - 44})`}
                      >
                        <rect
                          width={200}
                          height={56}
                          rx={8}
                          fill="var(--color-surface-raised)"
                          stroke="var(--color-edge)"
                        />
                        <text
                          x={10}
                          y={20}
                          fill="var(--color-content)"
                          className="text-[11px] font-semibold"
                        >
                          {node.label}
                        </text>
                        <text
                          x={10}
                          y={36}
                          fill="var(--color-content-muted)"
                          className="text-[10px]"
                        >
                          {formatBytes(node.bytes)} ·{" "}
                          {formatNumber(node.packets)} pkts
                        </text>
                        <text
                          x={10}
                          y={50}
                          fill="var(--color-content-muted)"
                          className="text-[10px]"
                        >
                          {formatNumber(node.connections)} connections
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}
          </svg>
        </div>

        {(hiddenEdgeCount > 0 || hiddenNodeCount > 0 || selectedNode) && (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-edge bg-surface-overlay/40 px-5 py-3 text-[11px] text-content-subtle">
            {hiddenEdgeCount > 0 && (
              <span>
                Showing the {visibleEdges.length} heaviest connections.{" "}
                <span className="text-content-muted">
                  {hiddenEdgeCount} more not drawn for clarity.
                </span>
              </span>
            )}
            {hiddenNodeCount > 0 && (
              <span>
                {totalDrawnNodes} of {topology.node_count} nodes shown.
              </span>
            )}
            {selectedNode && (
              <span className="text-accent">
                Focus: {selectedNode} — click again to clear.
              </span>
            )}
          </div>
        )}

        {selectedNodeData && (
          <div className="border-t border-edge bg-surface-overlay/40 px-6 py-5">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-content-subtle">
                  Selected host
                </p>
                <p className="mt-1 font-mono text-sm font-semibold text-content">
                  {selectedNodeData.label}
                </p>
                <p className="mt-1 text-xs text-content-subtle">
                  {classifyNodeZone(selectedNodeData) === "internal"
                    ? "Internal network system"
                    : classifyNodeZone(selectedNodeData) === "infrastructure"
                      ? "DNS / infrastructure system"
                      : "External network system"}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <div className="rounded-lg border border-edge bg-surface px-4 py-3">
                  <p className="text-[9px] uppercase tracking-wider text-content-subtle">
                    Packets
                  </p>
                  <p className="mt-1 text-sm font-semibold text-content tabular-nums">
                    {formatNumber(selectedNodeData.packets)}
                  </p>
                </div>
                <div className="rounded-lg border border-edge bg-surface px-4 py-3">
                  <p className="text-[9px] uppercase tracking-wider text-content-subtle">
                    Traffic
                  </p>
                  <p className="mt-1 text-sm font-semibold text-content tabular-nums">
                    {formatBytes(selectedNodeData.bytes)}
                  </p>
                </div>
                <div className="rounded-lg border border-edge bg-surface px-4 py-3">
                  <p className="text-[9px] uppercase tracking-wider text-content-subtle">
                    Connections
                  </p>
                  <p className="mt-1 text-sm font-semibold text-content tabular-nums">
                    {formatNumber(selectedNodeData.connections)}
                  </p>
                </div>
                <div className="rounded-lg border border-edge bg-surface px-4 py-3">
                  <p className="text-[9px] uppercase tracking-wider text-content-subtle">
                    Zone
                  </p>
                  <p className="mt-1 text-sm font-semibold capitalize text-content">
                    {classifyNodeZone(selectedNodeData)}
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </Panel>

      <Panel className="nfx-panel-enter">
        <PanelHeader
          title="Top communication paths"
          description="Highest-volume connections in the analyzed topology."
          actions={
            selectedNode ? (
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="inline-flex h-8 items-center rounded-lg border border-edge bg-surface-subtle px-3 text-[11px] font-medium text-content-muted hover:border-edge-strong hover:text-content"
              >
                Clear selection
              </button>
            ) : undefined
          }
        />
        <div className="overflow-x-auto">
          <table className="w-full min-w-[850px] text-left text-sm">
            <thead className="border-b border-edge bg-surface-overlay/40 text-[10px] uppercase tracking-wider text-content-subtle">
              <tr>
                {[
                  "Source",
                  "Direction",
                  "Destination",
                  "Protocol",
                  "Packets",
                  "Traffic",
                ].map((h) => (
                  <th key={h} className="px-6 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-edge">
              {visibleEdges
                .slice()
                .sort((a, b) => b.bytes - a.bytes)
                .slice(0, 15)
                .map((edge) => {
                  const source = topology.nodes.find(
                    (n) => n.id === edge.source
                  );
                  const target = topology.nodes.find(
                    (n) => n.id === edge.target
                  );
                  const selected =
                    selectedNode === edge.source ||
                    selectedNode === edge.target;

                  const sourceZone = source
                    ? classifyNodeZone(source)
                    : "external";
                  const targetZone = target
                    ? classifyNodeZone(target)
                    : "external";

                  return (
                    <tr
                      key={edge.id}
                      onClick={() => setSelectedNode(edge.source)}
                      className={`nfx-table-row cursor-pointer ${
                        selected ? "bg-surface-overlay/40" : ""
                      }`}
                    >
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <span
                            className="h-2.5 w-2.5 rounded-full"
                            style={{ background: zoneAccent[sourceZone] }}
                          />
                          <span className="font-mono text-xs text-content">
                            {edge.source}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2 text-content-subtle">
                          <span className="h-px w-8 bg-edge-strong" />
                          <span className="text-xs">→</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <span
                            className="h-2.5 w-2.5 rounded-full"
                            style={{ background: zoneAccent[targetZone] }}
                          />
                          <span className="font-mono text-xs text-content">
                            {edge.target}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="rounded-md border border-edge bg-surface-overlay px-2 py-1 text-[10px] font-semibold text-content-muted">
                          {edge.protocol}
                          {edge.destination_port
                            ? `:${edge.destination_port}`
                            : ""}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-xs tabular-nums text-content-muted">
                        {formatNumber(edge.packets)}
                      </td>
                      <td className="px-6 py-4 text-xs font-medium tabular-nums text-content">
                        {formatBytes(edge.bytes)}
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </Panel>

      {selectedNode && selectedEdges.length > 0 && (
        <Panel className="nfx-panel-enter">
          <PanelHeader
            title={`Focus: ${selectedNode}`}
            description={`${selectedEdges.length} related connections`}
          />
          <div className="grid gap-3 p-5">
            {selectedEdges.slice(0, 8).map((edge) => (
              <div
                key={edge.id}
                className="flex flex-col gap-3 rounded-lg border border-edge p-4 transition hover:border-edge-strong sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="flex items-center gap-3 font-mono text-xs text-content">
                  <span>{edge.source}</span>
                  <span className="text-content-subtle">→</span>
                  <span>{edge.target}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="rounded-md border border-edge bg-surface-overlay px-2 py-1 text-[10px] font-semibold text-content-muted">
                    {edge.protocol}
                  </span>
                  <span className="text-xs text-content-subtle tabular-nums">
                    {formatNumber(edge.packets)} packets
                  </span>
                  <span className="text-xs font-medium text-content tabular-nums">
                    {formatBytes(edge.bytes)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

/* =========================================================
   MAIN
========================================================= */

export default function CasePage() {
  const params = useParams();
  const router = useRouter();

  const caseId =
    typeof params.id === "string"
      ? params.id
      : Array.isArray(params.id)
        ? params.id[0]
        : "";

  const [caseData, setCaseData] = useState<Case | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(
    null
  );
  const [analysisMap, setAnalysisMap] = useState<
    Record<string, PcapAnalysis | null>
  >({});
  const [analysis, setAnalysis] = useState<PcapAnalysis | null>(null);
  const [hosts, setHosts] = useState<NetworkHost[]>([]);
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [dnsRecords, setDnsRecords] = useState<DNSRecord[]>([]);
  const [httpTransactions, setHttpTransactions] = useState<HTTPTransaction[]>(
    []
  );
  const [tlsSessions, setTlsSessions] = useState<TLSSession[]>([]);
  const [activeTab, setActiveTab] = useState<TabId>("overview");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [analyzingId, setAnalyzingId] = useState<string | null>(null);

  const subnavRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!caseId) return;
    let cancelled = false;

    (async () => {
      try {
        setLoading(true);
        setError(null);

        let currentCase: Case | null = null;
        try {
          currentCase = await getCaseById(caseId);
        } catch {
          const cases = await getCases();
          currentCase = cases.find((c) => c.id === caseId) ?? null;
        }

        if (!currentCase) throw new Error("Case not found");
        if (cancelled) return;

        setCaseData(currentCase);

        const evidenceData = await getCaseEvidence(caseId);
        if (cancelled) return;
        setEvidence(evidenceData);

        if (evidenceData.length > 0) {
          const firstId = evidenceData[0].id;
          setSelectedEvidenceId(firstId);

          const analyses = await Promise.all(
            evidenceData.map(async (item) => {
              try {
                const result = await getEvidenceAnalysis(caseId, item.id);
                return [item.id, result] as const;
              } catch {
                return [item.id, null] as const;
              }
            })
          );
          if (cancelled) return;
          const map = Object.fromEntries(analyses);
          setAnalysisMap(map);
          setAnalysis(map[firstId] ?? null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Unable to load case");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [caseId]);

  useEffect(() => {
    if (!caseId || !selectedEvidenceId) return;
    let cancelled = false;

    (async () => {
      const [hostsResult, flowsResult] = await Promise.all([
        getDiscoveredHosts(caseId, selectedEvidenceId).catch(
          () => [] as NetworkHost[]
        ),
        getEvidenceFlows(caseId, selectedEvidenceId, {
          limit: 100,
          offset: 0,
        }).catch(() => [] as NetworkFlow[]),
      ]);
      if (cancelled) return;
      setHosts(hostsResult);
      setFlows(flowsResult);
    })();

    return () => {
      cancelled = true;
    };
  }, [caseId, selectedEvidenceId]);

  /* Sticky subnav — toggle a shadow when scrolled */
  useEffect(() => {
    const el = subnavRef.current;
    if (!el) return;

    function onScroll() {
      if (!el) return;
      el.dataset.scrolled = window.scrollY > 8 ? "true" : "false";
    }

    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const handleAnalyze = useCallback(
    async (evidenceId: string) => {
      try {
        setAnalyzingId(evidenceId);
        setError(null);
        const result = await analyzeEvidence(caseId, evidenceId);
        setAnalysisMap((cur) => ({ ...cur, [evidenceId]: result }));
        setSelectedEvidenceId(evidenceId);
        setAnalysis(result);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Unable to analyze evidence"
        );
      } finally {
        setAnalyzingId(null);
      }
    },
    [caseId]
  );

  const handleUpload = useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;
      try {
        setUploading(true);
        setError(null);
        const uploaded = await uploadEvidence(caseId, file);
        setEvidence((cur) => [uploaded, ...cur]);
        setSelectedEvidenceId(uploaded.id);
        setAnalysisMap((cur) => ({ ...cur, [uploaded.id]: null }));
        setAnalysis(null);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Unable to upload evidence"
        );
      } finally {
        setUploading(false);
        event.target.value = "";
      }
    },
    [caseId]
  );

  const selectEvidence = useCallback(
    (id: string) => {
      setSelectedEvidenceId(id);
      setAnalysis(analysisMap[id] ?? null);
      setDnsRecords([]);
      setHttpTransactions([]);
      setTlsSessions([]);
    },
    [analysisMap]
  );

  const selectedEvidence =
    evidence.find((e) => e.id === selectedEvidenceId) ?? null;

  if (loading) {
    return (
      <main className="min-h-screen bg-surface text-content">
        <div className="mx-auto max-w-[1600px] px-4 py-16 sm:px-6 lg:px-8">
          <LoadingState label="Loading investigation…" />
        </div>
      </main>
    );
  }

  if (!caseData) {
    return (
      <main className="min-h-screen bg-surface text-content">
        <div className="mx-auto max-w-[1600px] px-4 py-16 sm:px-6 lg:px-8">
          <Panel className="nfx-panel-enter">
            <ErrorState
              title="Case not found"
              description={error ?? "The requested case could not be loaded."}
            />
          </Panel>
        </div>
      </main>
    );
  }

  const activeTabItem =
    ALL_TABS.find((t) => t.id === activeTab) ?? ALL_TABS[0];

  return (
    <main className="min-h-screen bg-surface text-content">
      {/* CASE HEADER — hero card with gradient border */}
      <section className="nfx-case-enter mx-auto mt-6 max-w-[1600px] px-4 sm:px-6 lg:px-8">
        <div className="nfx-case-hero relative">
          <span aria-hidden className="nfx-hero-sweep" />
          <div className="nfx-case-hero__inner p-6 sm:p-7">
            <button
              type="button"
              onClick={() => router.back()}
              className="mb-4 inline-flex items-center gap-1.5 text-xs font-medium text-content-muted transition hover:text-content"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Back to cases
            </button>

            <div className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-edge bg-surface px-2.5 py-1 font-mono text-[10px] font-medium text-content-muted">
                    {caseData.case_number}
                  </span>
                  <StatusBadge value={caseData.status} />
                  <SeverityBadge value={caseData.severity} />
                </div>
                <h1 className="mt-4 truncate text-2xl font-semibold tracking-tight text-content sm:text-3xl">
                  {caseData.name}
                </h1>
                {caseData.description && (
                  <p className="mt-2 max-w-2xl text-sm leading-6 text-content-muted">
                    {caseData.description}
                  </p>
                )}
              </div>

              <div className="w-full xl:w-[360px]">
                <label className="mb-2 block text-[10px] font-semibold uppercase tracking-[0.12em] text-content-subtle">
                  Active evidence
                </label>
                <div className="relative">
                  <select
                    value={selectedEvidenceId ?? ""}
                    onChange={(e) => selectEvidence(e.target.value)}
                    className="w-full appearance-none rounded-xl border border-edge bg-surface px-4 py-2.5 pr-10 text-xs font-medium text-content outline-none focus:border-accent"
                  >
                    {evidence.length === 0 ? (
                      <option value="">No evidence</option>
                    ) : (
                      evidence.map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.original_filename}
                        </option>
                      ))
                    )}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-content-subtle" />
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* TABS — sticky subnav */}
      <nav
        ref={subnavRef}
        data-scrolled="false"
        className="nfx-subnav mt-4"
      >
        <div className="mx-auto max-w-[1600px] px-4 py-2 sm:px-6 lg:px-8">
          <div className="nfx-tab-rail border-none bg-transparent shadow-none">
            {TAB_GROUPS.map((group, groupIndex) => (
              <div key={group.label} className="flex items-center">
                {groupIndex > 0 && (
                  <span className="nfx-tab-group-label">{group.label}</span>
                )}
                {group.items.map((tab) => {
                  const IconCmp = tab.icon;
                  const active = activeTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => setActiveTab(tab.id)}
                      aria-current={active ? "page" : undefined}
                      data-active={active}
                      className="nfx-tab"
                    >
                      <IconCmp className="h-4 w-4" />
                      <span>{tab.label}</span>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </nav>

      {/* CONTENT */}
      <section className="mx-auto max-w-[1600px] px-4 py-7 sm:px-6 lg:px-8">
        {error && (
          <div className="nfx-panel-enter mb-6 flex items-start justify-between gap-4 rounded-lg border border-severity-critical/30 bg-severity-critical/10 px-4 py-3 text-xs text-severity-critical">
            <span className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {error}
            </span>
            <button
              type="button"
              onClick={() => setError(null)}
              className="font-medium hover:underline"
            >
              Dismiss
            </button>
          </div>
        )}

        <div className="nfx-panel-enter mb-6">
          <SectionHeader
            eyebrow={`Case · ${caseData.case_number}`}
            title={activeTabItem.label}
            description={
              activeTab === "overview"
                ? "Case and evidence context, analysis status, and available forensic modules."
                : activeTab === "evidence"
                  ? "Upload, verify, and manage PCAP evidence for this case."
                  : activeTab === "analysis"
                    ? "Packet capture analysis summary."
                    : activeTab === "hosts"
                      ? "Hosts discovered from flow analysis."
                      : activeTab === "flows"
                        ? "Aggregated network conversations."
                        : activeTab === "topology"
                          ? "Directional communication between observed systems."
                          : activeTab === "protocols"
                            ? "DNS, HTTP, and TLS investigation."
                            : activeTab === "detections"
                              ? "Detections, indicators, timeline, and MITRE ATT&CK."
                              : "Case investigation workspace."
            }
          />
        </div>

        {activeTab === "overview" && (
          <OverviewTab
            evidence={evidence}
            analysisMap={analysisMap}
            selectedEvidence={selectedEvidence}
            analysis={analysis}
            hosts={hosts}
            flows={flows}
            dnsRecords={dnsRecords}
            httpTransactions={httpTransactions}
            tlsSessions={tlsSessions}
            onSelectEvidence={selectEvidence}
            onAnalyze={handleAnalyze}
          />
        )}

        {activeTab === "evidence" && (
          <EvidenceTab
            evidence={evidence}
            selectedEvidenceId={selectedEvidenceId}
            analysisMap={analysisMap}
            onSelect={selectEvidence}
            onAnalyze={handleAnalyze}
            onUpload={handleUpload}
            uploading={uploading}
            analyzingId={analyzingId}
          />
        )}

        {activeTab === "analysis" && <AnalysisTab analysis={analysis} />}

        {activeTab === "hosts" &&
          (selectedEvidence ? (
            <HostsTab
              caseId={caseId}
              evidenceId={selectedEvidence.id}
              analysis={analysis}
            />
          ) : (
            <Panel className="nfx-panel-enter">
              <EmptyState
                title="No evidence selected"
                description="Select a PCAP from the Evidence tab."
              />
            </Panel>
          ))}

        {activeTab === "flows" &&
          (selectedEvidence ? (
            <FlowsTab
              caseId={caseId}
              evidenceId={selectedEvidence.id}
              analysis={analysis}
            />
          ) : (
            <Panel className="nfx-panel-enter">
              <EmptyState
                title="No evidence selected"
                description="Select a PCAP from the Evidence tab."
              />
            </Panel>
          ))}

        {activeTab === "topology" &&
          (selectedEvidence ? (
            <TopologyTab
              caseId={caseId}
              evidenceId={selectedEvidence.id}
              analysis={analysis}
            />
          ) : (
            <Panel className="nfx-panel-enter">
              <EmptyState
                title="No evidence selected"
                description="Select a PCAP from the Evidence tab."
              />
            </Panel>
          ))}

        {activeTab === "protocols" &&
          (selectedEvidence ? (
            <ProtocolsTab
              caseId={caseId}
              evidenceId={selectedEvidence.id}
              analysis={analysis}
              dnsRecords={dnsRecords}
              httpTransactions={httpTransactions}
              tlsSessions={tlsSessions}
              setDnsRecords={setDnsRecords}
              setHttpTransactions={setHttpTransactions}
              setTlsSessions={setTlsSessions}
            />
          ) : (
            <Panel className="nfx-panel-enter">
              <EmptyState
                title="No evidence selected"
                description="Select a PCAP from the Evidence tab."
              />
            </Panel>
          ))}

        {activeTab === "detections" &&
          (selectedEvidence ? (
            <CaseIntelligenceTabs
              caseId={caseId}
              evidenceId={selectedEvidence.id}
            />
          ) : (
            <Panel className="nfx-panel-enter">
              <EmptyState
                title="No evidence selected"
                description="Select or upload evidence to load security intelligence."
              />
            </Panel>
          ))}

        {activeTab === "investigation" &&
          (selectedEvidence ? (
            <CaseInvestigationPanel
              caseId={caseId}
              evidenceId={selectedEvidence.id}
            />
          ) : (
            <Panel className="nfx-panel-enter">
              <EmptyState
                title="No evidence selected"
                description="Select or upload evidence before opening the investigation workspace."
                action={
                  <button
                    type="button"
                    onClick={() => setActiveTab("evidence")}
                    className="inline-flex h-9 items-center rounded-lg bg-accent px-4 text-xs font-semibold text-accent-foreground"
                  >
                    Open evidence
                  </button>
                }
              />
            </Panel>
          ))}
      </section>
    </main>
  );
}