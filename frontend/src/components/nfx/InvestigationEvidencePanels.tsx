
"use client";

import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { API_URL } from "@/lib/api";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Download,
  FileSearch,
  Fingerprint,
  Loader2,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  Target,
} from "lucide-react";

type RecordData = Record<string, unknown>;

type Props = {
  caseId: string;
  evidenceId?: string;
};

type Endpoint = "incident-reasoning" | "file-forensics";

const API_ROOT = API_URL.replace(/\/+$/, "").replace(/\/api\/v1$/, "");
const API_PREFIX = `${API_ROOT}/api/v1`;

function text(value: unknown, fallback = "—"): string {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }

  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }

  return String(value);
}

function list(value: unknown): RecordData[] {
  if (!Array.isArray(value)) return [];

  return value.filter(
    (item): item is RecordData =>
      typeof item === "object" &&
      item !== null &&
      !Array.isArray(item),
  );
}

function values(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function pick(item: RecordData, ...keys: string[]): unknown {
  for (const key of keys) {
    if (item[key] !== null && item[key] !== undefined) {
      return item[key];
    }
  }

  return undefined;
}

function record(value: unknown): RecordData {
  if (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  ) {
    return value as RecordData;
  }

  return {};
}

function numericValue(...candidates: unknown[]): number | undefined {
  for (const candidate of candidates) {
    if (
      typeof candidate === "number" &&
      Number.isFinite(candidate) &&
      candidate >= 0
    ) {
      return candidate;
    }
  }

  return undefined;
}

function prettyTime(value: unknown): string {
  if (!value) return "Time unavailable";

  const date = new Date(
    typeof value === "number" && value < 10_000_000_000
      ? value * 1000
      : String(value),
  );

  return Number.isNaN(date.getTime())
    ? text(value)
    : date.toLocaleString();
}

function bytes(value: unknown): string {
  const size = Number(value);

  if (!Number.isFinite(size) || size < 0) {
    return "Size unavailable";
  }

  if (size < 1024) return `${size} B`;

  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }

  if (size < 1024 * 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(2)} MB`;
  }

  return `${(size / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function humanize(value: unknown): string {
  return text(value, "Unknown").replace(/_/g, " ");
}

function Panel({
  title,
  description,
  icon,
  children,
  action,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="overflow-hidden rounded-xl border border-edge bg-surface">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-edge px-5 py-4">
        <div className="flex items-start gap-3">
          {icon && <span className="mt-0.5 text-accent">{icon}</span>}

          <div>
            <h3 className="font-semibold text-content">{title}</h3>

            {description && (
              <p className="mt-1 text-sm leading-5 text-content-muted">
                {description}
              </p>
            )}
          </div>
        </div>

        {action}
      </div>

      <div className="p-5">{children}</div>
    </section>
  );
}

function Pill({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "danger" | "warning" | "success" | "accent";
}) {
  const tones = {
    neutral: "border-edge bg-surface-subtle text-content-muted",
    danger:
      "border-severity-critical/30 bg-severity-critical/10 text-severity-critical",
    warning:
      "border-severity-medium/30 bg-severity-medium/10 text-severity-medium",
    success:
      "border-status-verified/30 bg-status-verified/10 text-status-verified",
    accent: "border-accent/30 bg-accent/10 text-accent",
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold capitalize ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

function Empty({
  title,
  detail,
}: {
  title: string;
  detail: string;
}) {
  return (
    <div className="rounded-lg border border-dashed border-edge p-8 text-center">
      <FileSearch className="mx-auto h-7 w-7 text-content-subtle" />

      <p className="mt-3 text-sm font-medium text-content">{title}</p>

      <p className="mx-auto mt-1 max-w-xl text-sm leading-6 text-content-muted">
        {detail}
      </p>
    </div>
  );
}

function ErrorBox({ message }: { message: string }) {
  if (!message) return null;

  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-lg border border-severity-critical/30 bg-severity-critical/10 p-3 text-sm text-severity-critical"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <p className="break-words">{message}</p>
    </div>
  );
}

function NoticeList({
  title,
  items,
}: {
  title: string;
  items: unknown[];
}) {
  if (!items.length) return null;

  return (
    <div className="rounded-lg border border-edge bg-surface-subtle/50 p-4">
      <p className="text-sm font-semibold text-content">{title}</p>

      <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-content-muted">
        {items.map((item, index) => (
          <li key={`${index}-${text(item)}`}>{text(item)}</li>
        ))}
      </ul>
    </div>
  );
}

function Metric({
  label,
  value,
  detail,
}: {
  label: string;
  value: unknown;
  detail?: string;
}) {
  return (
    <div className="rounded-xl border border-edge bg-surface-subtle/50 p-4">
      <p className="text-xs uppercase tracking-wider text-content-subtle">
        {label}
      </p>

      <p className="mt-2 break-words text-2xl font-semibold tabular-nums text-content">
        {text(value, "0")}
      </p>

      {detail && (
        <p className="mt-1 text-xs leading-5 text-content-muted">
          {detail}
        </p>
      )}
    </div>
  );
}

function ArtifactReasons({
  item,
}: {
  item: RecordData;
}) {
  const reasons = [
    ...values(item.suspicious_reasons),
    ...values(item.reasons),
  ];

  const singleReason = pick(item, "suspicious_reason", "reason");

  if (!reasons.length && singleReason === undefined) {
    return null;
  }

  return (
    <div className="mt-3 rounded-lg border border-severity-medium/30 bg-severity-medium/5 p-3">
      <p className="text-xs font-semibold text-severity-medium">
        Reasons flagged by the backend
      </p>

      {reasons.length > 0 ? (
        <ul className="mt-2 list-disc space-y-1 pl-5 text-xs leading-5 text-content-muted">
          {reasons.map((reason, index) => (
            <li key={`${index}-${text(reason)}`}>{text(reason)}</li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-xs leading-5 text-content-muted">
          {text(singleReason)}
        </p>
      )}
    </div>
  );
}

function useEvidenceEndpoint(
  caseId: string,
  evidenceId: string | undefined,
  endpoint: Endpoint,
) {
  const [data, setData] = useState<RecordData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const run = useCallback(async () => {
    if (!caseId || !evidenceId?.trim()) {
      setError(
        "Select or enter an evidence ID in the investigation workspace first.",
      );
      return;
    }

    setLoading(true);
    setError("");

    try {
      const path =
        `/cases/${encodeURIComponent(caseId)}` +
        `/evidence/${encodeURIComponent(evidenceId.trim())}` +
        `/${endpoint}/analyze`;

      const response = await fetch(`${API_PREFIX}${path}`, {
        method: "POST",
        headers: { Accept: "application/json" },
        cache: "no-store",
      });

      if (!response.ok) {
        const body = await response.text();

        throw new Error(
          `Request failed (${response.status}): ${body.slice(0, 400)}`,
        );
      }

      const result: unknown = await response.json();

      if (
        typeof result !== "object" ||
        result === null ||
        Array.isArray(result)
      ) {
        throw new Error("The API returned an unexpected response format.");
      }

      setData(result as RecordData);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to run analysis.",
      );
    } finally {
      setLoading(false);
    }
  }, [caseId, evidenceId, endpoint]);

  useEffect(() => {
    setData(null);
    setError("");
  }, [caseId, evidenceId, endpoint]);

  return { data, loading, error, run };
}

export function IncidentReasoningPanel({
  caseId,
  evidenceId,
}: Props) {
  const { data, loading, error, run } = useEvidenceEndpoint(
    caseId,
    evidenceId,
    "incident-reasoning",
  );

  const sequence = list(data?.probable_sequence);
  const iocs = list(data?.matched_iocs);
  const downloads = list(data?.suspicious_downloads);
  const detections = list(data?.detections);
  const narrativeStages = list(data?.narrative);
  const recoveredArtifacts = list(data?.recovered_file_artifacts);

  const statistics = record(data?.statistics);

  const recommendations = values(data?.recommended_steps);
  const limitations = values(data?.limitations);

  const confidence = pick(data ?? {}, "overall_confidence", "confidence");

  const matchedIndicatorCount =
    numericValue(
      statistics.http_ioc_matches,
      data?.http_ioc_matches,
    ) ?? iocs.length;

  const suspiciousTransferCount =
    numericValue(
      statistics.suspicious_downloads,
      statistics.suspicious_transfers,
      data?.suspicious_download_count,
      data?.suspicious_transfer_count,
    ) ?? downloads.length;

  return (
    <div className="space-y-5">
      <Panel
        title="AI-assisted incident reasoning"
        description="Correlates existing detections, packet metadata, indicators, and timeline records into a structured incident assessment."
        icon={<Sparkles className="h-5 w-5" />}
        action={
          <button
            type="button"
            onClick={() => void run()}
            disabled={loading || !evidenceId?.trim()}
            className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-xs font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}

            {loading
              ? "Investigating…"
              : data
                ? "Run again"
                : "Run investigation"}
          </button>
        }
      >
        <ErrorBox message={error} />

        {!evidenceId?.trim() ? (
          <Empty
            title="Evidence selection required"
            detail="Enter an evidence ID at the top of the Case Investigation workspace before running incident reasoning."
          />
        ) : loading && !data ? (
          <div className="flex items-center justify-center gap-3 py-12 text-sm text-content-muted">
            <Loader2 className="h-5 w-5 animate-spin text-accent" />
            Correlating available forensic records…
          </div>
        ) : !data ? (
          <Empty
            title="Incident assessment not generated"
            detail="Run the investigation to correlate the backend's available evidence. The result is an evidence-based assessment, not proof of attribution."
          />
        ) : (
          <div className="space-y-5">
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <Metric
                label="Analysis type"
                value={humanize(data.analysis_type)}
                detail="Method reported by the backend"
              />

              <Metric
                label="Assessment confidence"
                value={text(confidence, "Not supplied")}
                detail="Backend indicator, not a calibrated probability of compromise"
              />

              <Metric
                label="Matched indicators"
                value={matchedIndicatorCount}
                detail="HTTP IOC matches when reported; otherwise returned IOC records"
              />

              <Metric
                label="Suspicious transfers"
                value={suspiciousTransferCount}
                detail="Transfer findings reported by the backend"
              />
            </div>

            <Panel
              title="Incident assessment"
              description="A structured interpretation of the records returned by the backend."
              icon={<Target className="h-5 w-5" />}
            >
              {narrativeStages.length > 0 ? (
                <div className="space-y-3">
                  {narrativeStages.map((stage, index) => (
                    <article
                      key={String(pick(stage, "id", "stage") ?? index)}
                      className="rounded-lg border border-edge bg-surface-subtle/40 p-4"
                    >
                      <p className="text-xs font-semibold uppercase tracking-wider text-accent">
                        {text(
                          pick(stage, "stage", "title"),
                          `Assessment stage ${index + 1}`,
                        )}
                      </p>

                      <p className="mt-2 whitespace-pre-wrap break-words text-sm leading-7 text-content-muted">
                        {text(
                          pick(
                            stage,
                            "finding",
                            "details",
                            "description",
                            "summary",
                          ),
                        )}
                      </p>
                    </article>
                  ))}
                </div>
              ) : (
                <p className="whitespace-pre-wrap break-words text-sm leading-7 text-content-muted">
                  {text(
                    data.narrative ?? data.summary,
                    "The backend did not return an incident narrative.",
                  )}
                </p>
              )}

              <p className="mt-4 text-xs leading-5 text-content-subtle">
                Findings reflect the records available to the backend.
                Detection severity, suspicious file signatures, and IP
                frequency are investigation leads; they do not independently
                establish compromise, attacker identity, or execution.
              </p>
            </Panel>

            {recoveredArtifacts.length > 0 && (
              <Panel
                title="Recovered file evidence"
                description={`${recoveredArtifacts.length} recovered-file artifact records returned by the incident reasoning service.`}
                icon={<Fingerprint className="h-5 w-5" />}
              >
                <div className="space-y-3">
                  {recoveredArtifacts.map((item, index) => {
                    const isSuspicious = item.suspicious === true;
                    const isRecovered = item.recovered === true;
                    const sha256 = pick(
                      item,
                      "sha256",
                      "file_hash",
                      "hash",
                    );

                    return (
                      <article
                        key={String(
                          pick(item, "artifact_id", "id", "filename") ??
                            index,
                        )}
                        className="rounded-lg border border-edge p-4"
                      >
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <p className="break-all font-medium text-content">
                            {text(
                              pick(item, "filename", "original_filename"),
                              `Recovered artifact ${index + 1}`,
                            )}
                          </p>

                          <div className="flex flex-wrap gap-2">
                            <Pill tone={isRecovered ? "success" : "neutral"}>
                              {isRecovered
                                ? "Recovered"
                                : "Recovery not confirmed"}
                            </Pill>

                            {isSuspicious && (
                              <Pill tone="warning">Requires review</Pill>
                            )}
                          </div>
                        </div>

                        <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                          <div>
                            <p className="text-[11px] uppercase tracking-wider text-content-subtle">
                              Detected type
                            </p>
                            <p className="mt-1 break-all text-sm text-content-muted">
                              {text(
                                pick(
                                  item,
                                  "detected_file_type",
                                  "detected_type",
                                  "file_extension",
                                ),
                                "Not identified",
                              )}
                            </p>
                          </div>

                          <div>
                            <p className="text-[11px] uppercase tracking-wider text-content-subtle">
                              Declared MIME type
                            </p>
                            <p className="mt-1 break-all text-sm text-content-muted">
                              {text(
                                pick(
                                  item,
                                  "declared_mime_type",
                                  "mime_type",
                                  "content_type",
                                ),
                                "Not supplied",
                              )}
                            </p>
                          </div>

                          <div>
                            <p className="text-[11px] uppercase tracking-wider text-content-subtle">
                              File size
                            </p>
                            <p className="mt-1 text-sm text-content-muted">
                              {bytes(pick(item, "size_bytes", "size"))}
                            </p>
                          </div>

                          <div>
                            <p className="text-[11px] uppercase tracking-wider text-content-subtle">
                              Source IP
                            </p>
                            <p className="mt-1 break-all text-sm text-content-muted">
                              {text(pick(item, "source_ip", "src_ip"))}
                            </p>
                          </div>

                          <div>
                            <p className="text-[11px] uppercase tracking-wider text-content-subtle">
                              Destination IP
                            </p>
                            <p className="mt-1 break-all text-sm text-content-muted">
                              {text(pick(item, "destination_ip", "dst_ip"))}
                            </p>
                          </div>

                          <div>
                            <p className="text-[11px] uppercase tracking-wider text-content-subtle">
                              HTTP status / timestamp
                            </p>
                            <p className="mt-1 text-sm text-content-muted">
                              {text(
                                pick(item, "http_status", "status_code"),
                                "Status unavailable",
                              )}
                              {" · "}
                              {prettyTime(
                                pick(item, "timestamp", "first_seen"),
                              )}
                            </p>
                          </div>
                        </div>

                        {sha256 !== undefined && (
                          <div className="mt-3 rounded-lg bg-surface-subtle/60 p-3">
                            <p className="text-[11px] uppercase tracking-wider text-content-subtle">
                              SHA-256
                            </p>
                            <p className="mt-1 break-all font-mono text-xs leading-5 text-content-muted">
                              {text(sha256)}
                            </p>
                          </div>
                        )}

                        <ArtifactReasons item={item} />
                      </article>
                    );
                  })}
                </div>
              </Panel>
            )}

            {sequence.length > 0 && (
              <Panel
                title="Probable incident sequence"
                description="Review each step against its supporting timestamp and source records."
                icon={<Clock className="h-5 w-5" />}
              >
                <div className="relative ml-2 space-y-0 border-l border-edge pl-6">
                  {sequence.map((item, index) => (
                    <div
                      key={String(
                        pick(item, "id", "event_id") ?? index,
                      )}
                      className="relative pb-6 last:pb-0"
                    >
                      <span className="absolute -left-[31px] top-1 h-3 w-3 rounded-full border-2 border-accent bg-surface" />

                      <div className="flex flex-wrap items-center gap-2">
                        <Pill tone="accent">
                          {text(
                            pick(item, "stage", "event_type", "type"),
                            `Step ${index + 1}`,
                          )}
                        </Pill>

                        {pick(item, "confidence") !== undefined && (
                          <Pill>
                            Confidence: {text(pick(item, "confidence"))}
                          </Pill>
                        )}
                      </div>

                      <p className="mt-2 font-medium text-content">
                        {text(
                          pick(item, "title", "name", "description"),
                          `Sequence step ${index + 1}`,
                        )}
                      </p>

                      <p className="mt-1 text-sm leading-6 text-content-muted">
                        {text(
                          pick(
                            item,
                            "details",
                            "description",
                            "evidence",
                            "reason",
                          ),
                        )}
                      </p>

                      <p className="mt-2 text-xs text-content-subtle">
                        {prettyTime(
                          pick(item, "timestamp", "time", "first_seen"),
                        )}
                      </p>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            <Panel
              title="Suspicious downloads and transfers"
              description="Transfer metadata and file observations returned by the incident reasoning service."
              icon={<Download className="h-5 w-5" />}
            >
              {downloads.length > 0 ? (
                <div className="space-y-3">
                  {downloads.map((item, index) => (
                    <article
                      key={String(
                        pick(item, "id", "artifact_id", "uri") ?? index,
                      )}
                      className="rounded-lg border border-edge p-4"
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <p className="break-all font-medium text-content">
                          {text(
                            pick(item, "filename", "uri", "url", "host"),
                            `Transfer ${index + 1}`,
                          )}
                        </p>

                        <Pill tone="warning">Review required</Pill>
                      </div>

                      <div className="mt-3 grid gap-2 text-xs text-content-muted sm:grid-cols-2">
                        <p>
                          Source:{" "}
                          {text(pick(item, "source_ip", "src_ip"))}
                        </p>
                        <p>
                          Destination:{" "}
                          {text(pick(item, "destination_ip", "dst_ip"))}
                        </p>
                        <p>Host: {text(item.host)}</p>
                        <p>
                          HTTP status:{" "}
                          {text(
                            pick(item, "http_status", "status_code"),
                          )}
                        </p>
                        <p>
                          File type:{" "}
                          {text(
                            pick(
                              item,
                              "detected_file_type",
                              "file_extension",
                              "mime_type",
                            ),
                          )}
                        </p>
                        <p>
                          Time:{" "}
                          {prettyTime(
                            pick(item, "timestamp", "first_seen"),
                          )}
                        </p>
                      </div>

                      <ArtifactReasons item={item} />
                    </article>
                  ))}
                </div>
              ) : (
                <Empty
                  title="No suspicious transfers returned"
                  detail="This does not prove that the capture contains no malicious transfers. Check file forensics, HTTP records, and the analysis limitations."
                />
              )}
            </Panel>

            <Panel
              title="Correlated indicators of compromise"
              description="Indicators the backend associated with this evidence."
              icon={<ShieldAlert className="h-5 w-5" />}
            >
              {iocs.length > 0 ? (
                <div className="space-y-3">
                  {iocs.map((item, index) => {
                    const severity = String(
                      item.severity ?? "",
                    ).toLowerCase();

                    return (
                      <article
                        key={String(
                          pick(item, "id", "value", "indicator") ?? index,
                        )}
                        className="rounded-lg border border-edge p-4"
                      >
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <p className="break-all font-mono text-sm text-accent">
                            {text(
                              pick(item, "value", "indicator", "ioc"),
                            )}
                          </p>

                          <Pill
                            tone={
                              severity === "critical" || severity === "high"
                                ? "danger"
                                : "neutral"
                            }
                          >
                            {humanize(item.severity)}
                          </Pill>
                        </div>

                        <p className="mt-2 text-xs text-content-muted">
                          Type: {humanize(pick(item, "ioc_type", "type"))}
                          {" · "}Occurrences:{" "}
                          {text(item.occurrences, "Unknown")}
                          {" · "}Confidence:{" "}
                          {text(item.confidence, "Not supplied")}
                        </p>
                      </article>
                    );
                  })}
                </div>
              ) : (
                <Empty
                  title="No matched IOCs returned"
                  detail="The service did not return correlated indicators for this run."
                />
              )}
            </Panel>

            <Panel
              title="Correlated detections"
              description={`${detections.length} detection records returned by this reasoning run.`}
            >
              {detections.length > 0 ? (
                <div className="space-y-3">
                  {detections.map((item, index) => (
                    <article
                      key={String(
                        pick(item, "id", "detection_id") ?? index,
                      )}
                      className="rounded-lg border border-edge p-4"
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <p className="font-medium text-content">
                          {text(
                            pick(
                              item,
                              "title",
                              "name",
                              "detection_type",
                            ),
                            `Detection ${index + 1}`,
                          )}
                        </p>

                        <Pill tone="warning">
                          {humanize(item.severity)}
                        </Pill>
                      </div>

                      <p className="mt-2 text-sm leading-6 text-content-muted">
                        {text(pick(item, "description", "message"))}
                      </p>

                      <p className="mt-2 text-xs text-content-subtle">
                        {prettyTime(
                          pick(item, "timestamp", "created_at"),
                        )}
                        {" · "}Source: {text(item.source_ip)}
                        {" · "}Destination: {text(item.destination_ip)}
                      </p>
                    </article>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-content-muted">
                  No detections were returned in this reasoning response.
                </p>
              )}
            </Panel>

            <Panel
              title="Recommended investigation steps"
              description="Suggested analyst actions. Validate them against the original evidence before making incident decisions."
              icon={<CheckCircle2 className="h-5 w-5" />}
            >
              {recommendations.length > 0 ? (
                <ol className="list-decimal space-y-2 pl-5 text-sm leading-6 text-content-muted">
                  {recommendations.map((item, index) => (
                    <li key={index}>{text(item)}</li>
                  ))}
                </ol>
              ) : (
                <p className="text-sm text-content-muted">
                  No recommendations were returned by the backend.
                </p>
              )}
            </Panel>

            <NoticeList
              title="Analysis limitations"
              items={limitations}
            />
          </div>
        )}
      </Panel>
    </div>
  );
}

export function FileForensicsPanel({
  caseId,
  evidenceId,
}: Props) {
  const { data, loading, error, run } = useEvidenceEndpoint(
    caseId,
    evidenceId,
    "file-forensics",
  );

  const statistics = record(data?.statistics);

  const artifacts = list(data?.artifacts);
  const recoveredArtifacts = list(data?.recovered_file_artifacts);
  const suspicious = list(data?.suspicious_artifacts);
  const recoveredList = list(data?.recovered_files);
  const metadata = list(data?.metadata_artifacts);

  // Prefer the primary inventory. Fall back to the new recovered-file
  // response field when the legacy artifacts field is absent or empty.
  const displayArtifacts =
    artifacts.length > 0
      ? artifacts
      : recoveredArtifacts.length > 0
        ? recoveredArtifacts
        : recoveredList;

  const warnings = values(data?.warnings);
  const limitations = values(data?.limitations);

  const recoveredCountFromPayload =
    typeof data?.recovered_files === "number"
      ? data.recovered_files
      : undefined;

  const artifactCount =
    numericValue(
      data?.file_artifacts_examined,
      statistics.file_artifacts_examined,
    ) ??
    (displayArtifacts.length > 0
      ? displayArtifacts.length
      : recoveredList.length + metadata.length);

  const recoveredCount =
    numericValue(
      data?.recovered_files_count,
      statistics.recovered_files,
      recoveredCountFromPayload,
      data?.recovered_file_count,
    ) ??
    (recoveredList.length > 0
      ? recoveredList.length
      : displayArtifacts.filter((item) => item.recovered === true).length);

  const suspiciousCount =
    numericValue(
      data?.suspicious_recovered_files,
      statistics.suspicious_recovered_files,
    ) ??
    (suspicious.length > 0
      ? suspicious.length
      : displayArtifacts.filter((item) => item.suspicious === true).length);

  const transactionsExamined =
    numericValue(
      data?.transactions_examined,
      statistics.transactions_examined,
    );

  return (
    <div className="space-y-5">
      <Panel
        title="Transferred file analysis"
        description="Analyze supported network captures for recoverable files and file-transfer metadata."
        icon={<FileSearch className="h-5 w-5" />}
        action={
          <button
            type="button"
            onClick={() => void run()}
            disabled={loading || !evidenceId?.trim()}
            className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-xs font-semibold text-accent-foreground transition hover:bg-accent-muted disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}

            {loading
              ? "Analyzing…"
              : data
                ? "Analyze again"
                : "Analyze files"}
          </button>
        }
      >
        <ErrorBox message={error} />

        {!evidenceId?.trim() ? (
          <Empty
            title="Evidence selection required"
            detail="Enter an evidence ID in the main investigation workspace to analyze its PCAP or supported network evidence."
          />
        ) : loading && !data ? (
          <div className="flex items-center justify-center gap-3 py-12 text-sm text-content-muted">
            <Loader2 className="h-5 w-5 animate-spin text-accent" />
            Inspecting transfers and supported file signatures…
          </div>
        ) : !data ? (
          <Empty
            title="File analysis has not run"
            detail="Run file analysis to inspect the selected evidence. Recovery depends on supported protocols, available payload bytes, and the capture contents."
          />
        ) : (
          <div className="space-y-5">
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <Metric
                label="Artifacts"
                value={artifactCount}
                detail="Recovered and metadata-only records"
              />

              <Metric
                label="Recovered files"
                value={recoveredCount}
                detail="Reported as recovered by the service"
              />

              <Metric
                label="Suspicious artifacts"
                value={suspiciousCount}
                detail="Require manual validation"
              />

              <Metric
                label="Transactions examined"
                value={transactionsExamined ?? "Not supplied"}
                detail="Reported by the backend"
              />
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-edge bg-surface-subtle/50 p-4">
                <p className="text-xs uppercase tracking-wider text-content-subtle">
                  PCAP status
                </p>

                <div className="mt-2 flex items-center gap-2">
                  {data.pcap_found === true ? (
                    <CheckCircle2 className="h-4 w-4 text-status-verified" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-severity-medium" />
                  )}

                  <p className="text-sm font-medium text-content">
                    {data.pcap_found === true
                      ? "Capture located"
                      : data.pcap_found === false
                        ? "Capture not located"
                        : "Status not supplied"}
                  </p>
                </div>

                <p className="mt-2 break-all text-xs text-content-muted">
                  Evidence: {text(data.evidence_filename)}
                </p>
              </div>

              <div className="rounded-lg border border-edge bg-surface-subtle/50 p-4">
                <p className="text-xs uppercase tracking-wider text-content-subtle">
                  Recovery scope
                </p>

                <p className="mt-2 text-sm leading-6 text-content-muted">
                  Only supported, recoverable plaintext payloads can be
                  reconstructed. Metadata-only records are not recovered
                  files.
                </p>
              </div>
            </div>

            <NoticeList title="Analysis warnings" items={warnings} />

            <Panel
              title="Artifact inventory"
              description="Review recovered files and metadata-only transfer records separately."
              icon={<Fingerprint className="h-5 w-5" />}
            >
              {displayArtifacts.length > 0 ? (
                <div className="space-y-4">
                  {displayArtifacts.map((item, index) => {
                    const isRecovered = item.recovered === true;
                    const isSuspicious = item.suspicious === true;

                    return (
                      <article
                        key={String(
                          pick(
                            item,
                            "artifact_id",
                            "id",
                            "filename",
                            "sha256",
                          ) ?? index,
                        )}
                        className="rounded-xl border border-edge p-4 transition hover:border-edge-strong"
                      >
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="flex min-w-0 items-start gap-3">
                            <span className="rounded-lg bg-surface-overlay p-2 text-accent">
                              <FileSearch className="h-5 w-5" />
                            </span>

                            <div className="min-w-0">
                              <p className="break-all font-medium text-content">
                                {text(
                                  pick(
                                    item,
                                    "filename",
                                    "original_filename",
                                  ),
                                  `Artifact ${index + 1}`,
                                )}
                              </p>

                              <p className="mt-1 break-all text-xs text-content-muted">
                                {text(
                                  pick(
                                    item,
                                    "detected_file_type",
                                    "detected_type",
                                    "file_extension",
                                    "declared_mime_type",
                                    "mime_type",
                                  ),
                                  "File type not identified",
                                )}
                              </p>
                            </div>
                          </div>

                          <div className="flex flex-wrap gap-2">
                            <Pill
                              tone={isRecovered ? "success" : "neutral"}
                            >
                              {isRecovered
                                ? "Recovered"
                                : "Metadata only"}
                            </Pill>

                            {isSuspicious && (
                              <Pill tone="danger">Suspicious</Pill>
                            )}
                          </div>
                        </div>

                        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                          {[
                            [
                              "Size",
                              bytes(
                                pick(item, "size_bytes", "size"),
                              ),
                            ],
                            [
                              "HTTP status",
                              text(
                                pick(
                                  item,
                                  "http_status",
                                  "status_code",
                                ),
                              ),
                            ],
                            [
                              "Source IP",
                              text(
                                pick(item, "source_ip", "src_ip"),
                              ),
                            ],
                            [
                              "Destination IP",
                              text(
                                pick(item, "destination_ip", "dst_ip"),
                              ),
                            ],
                            ["Host", text(item.host)],
                            [
                              "Timestamp",
                              prettyTime(
                                pick(
                                  item,
                                  "timestamp",
                                  "first_seen",
                                ),
                              ),
                            ],
                          ].map(([label, value]) => (
                            <div key={label} className="min-w-0">
                              <p className="text-[11px] uppercase tracking-wider text-content-subtle">
                                {label}
                              </p>

                              <p className="mt-1 break-all text-sm text-content-muted">
                                {value}
                              </p>
                            </div>
                          ))}
                        </div>

                        {pick(item, "sha256", "file_hash", "hash") !==
                          undefined && (
                          <div className="mt-3 rounded-lg bg-surface-subtle/60 p-3">
                            <p className="text-[11px] uppercase tracking-wider text-content-subtle">
                              SHA-256
                            </p>

                            <p className="mt-1 break-all font-mono text-xs leading-5 text-content-muted">
                              {text(
                                pick(
                                  item,
                                  "sha256",
                                  "file_hash",
                                  "hash",
                                ),
                              )}
                            </p>
                          </div>
                        )}

                        <ArtifactReasons item={item} />
                      </article>
                    );
                  })}
                </div>
              ) : (
                <Empty
                  title="No artifact records returned"
                  detail="The analysis did not return any artifact entries. Review warnings and limitations, and confirm that the selected evidence is a supported capture file."
                />
              )}
            </Panel>

            {!!(metadata.length || recoveredList.length) &&
              !displayArtifacts.length && (
                <Panel
                  title="Artifact summary"
                  description="The backend returned categorized artifact lists but no combined inventory."
                >
                  <div className="space-y-2 text-sm text-content-muted">
                    <p>Recovered file records: {recoveredList.length}</p>
                    <p>Metadata-only records: {metadata.length}</p>
                    <p>
                      Check the raw API response if you need fields not shown
                      in this summary.
                    </p>
                  </div>
                </Panel>
              )}

            <NoticeList
              title="Forensic limitations"
              items={limitations}
            />

            <div className="rounded-lg border border-edge bg-surface-subtle/40 p-4">
              <p className="text-sm font-semibold text-content">
                Forensic handling note
              </p>

              <p className="mt-2 text-sm leading-6 text-content-muted">
                A filename or executable signature is a lead, not proof of
                maliciousness. Validate suspicious artifacts with their
                hashes, source and destination context, protocol metadata,
                and approved malware-analysis procedures. HTTPS payloads
                generally cannot be reconstructed from a PCAP alone without
                suitable decryption material or another authorized plaintext
                source.
              </p>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
