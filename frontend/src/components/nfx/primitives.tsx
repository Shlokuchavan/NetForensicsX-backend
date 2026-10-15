"use client";

import type { ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileSearch,
  Loader2,
  RefreshCw,
} from "lucide-react";

/* ------------------------------------------------------------------ */
/* Formatters                                                          */
/* ------------------------------------------------------------------ */

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatBytes(bytes: number | null | undefined): string {
  if (!Number.isFinite(bytes ?? NaN) || (bytes ?? 0) <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(
    Math.floor(Math.log(bytes as number) / Math.log(1024)),
    units.length - 1
  );
  return `${((bytes as number) / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

export function formatTimestamp(value: number | string | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  const numeric = typeof value === "number" ? value : Number(value);
  const date = Number.isFinite(numeric)
    ? new Date(numeric < 100_000_000_000 ? numeric * 1000 : numeric)
    : new Date(value as string);
  if (Number.isNaN(date.getTime())) return "Invalid timestamp";
  return date.toLocaleString();
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function humanize(value: string | null | undefined): string {
  if (!value) return "Unknown";
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

/* ------------------------------------------------------------------ */
/* Panel                                                               */
/* ------------------------------------------------------------------ */
export function Panel({
  children,
  className = "",
  elevated = false,
}: {
  children: ReactNode;
  className?: string;
  elevated?: boolean;
}) {
  return (
    <section
      className={[
        "group relative rounded-2xl border border-edge",
        "nfx-glass",
        // inner top highlight + soft depth
        "shadow-[inset_0_1px_0_0_color-mix(in_oklab,white_5%,transparent),0_1px_0_0_color-mix(in_oklab,var(--color-edge)_60%,transparent),0_12px_32px_-20px_rgb(0_0_0_/_0.5)]",
        elevated ? "shadow-raised" : "",
        "transition duration-[160ms] ease-[cubic-bezier(0.22,1,0.36,1)]",
        "hover:border-[color-mix(in_oklab,var(--color-accent)_22%,var(--color-edge))]",
        "hover:shadow-[inset_0_1px_0_0_color-mix(in_oklab,white_6%,transparent),0_1px_0_0_color-mix(in_oklab,var(--color-edge)_60%,transparent),0_16px_40px_-24px_color-mix(in_oklab,var(--color-accent)_45%,transparent)]",
        "animate-[nfx-fade-in_180ms_cubic-bezier(0.22,1,0.36,1)]",
        className,
      ].join(" ")}
    >
      {/* subtle accent hairline along the top */}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-x-6 top-0 h-px rounded-full opacity-0 transition-opacity duration-200 group-hover:opacity-100"
        style={{
          background:
            "linear-gradient(to right, transparent, color-mix(in oklab, var(--color-accent) 60%, transparent), transparent)",
        }}
      />
      {children}
    </section>
  );
}
export function PanelHeader({
  icon,
  title,
  description,
  actions,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-4 border-b border-edge p-5 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-center gap-3">
        {icon && (
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-surface-overlay text-accent">
            {icon}
          </div>
        )}
        <div className="min-w-0">
          <h3 className="truncate font-semibold text-content">{title}</h3>
          {description && (
            <p className="mt-1 text-xs text-content-subtle">{description}</p>
          )}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function SectionHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        {eyebrow && (
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-accent">
            {eyebrow}
          </p>
        )}
        <h2 className="mt-2 text-2xl font-semibold tracking-tight text-content">
          {title}
        </h2>
        {description && (
          <p className="mt-2 max-w-2xl text-sm leading-6 text-content-muted">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Badges                                                              */
/* ------------------------------------------------------------------ */

type SeverityTone = "critical" | "high" | "medium" | "low" | "info";

const severityToneClass: Record<SeverityTone, string> = {
  critical: "border-severity-critical/30 bg-severity-critical/10 text-severity-critical",
  high:     "border-severity-high/30 bg-severity-high/10 text-severity-high",
  medium:   "border-severity-medium/30 bg-severity-medium/10 text-severity-medium",
  low:      "border-severity-low/30 bg-severity-low/10 text-severity-low",
  info:     "border-edge bg-surface-overlay text-content-muted",
};

export function SeverityBadge({
  value,
  className = "",
}: {
  value: string | null | undefined;
  className?: string;
}) {
  const n = (value ?? "").toLowerCase();
  const tone: SeverityTone =
    n === "critical" ? "critical"
    : n === "high" ? "high"
    : n === "medium" ? "medium"
    : n === "low" ? "low"
    : "info";

  return (
    <span
      className={[
        "inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium tabular-nums",
        severityToneClass[tone],
        className,
      ].join(" ")}
    >
      {humanize(value ?? "unknown")}
    </span>
  );
}

type StatusTone = "verified" | "pending" | "failed" | "neutral";

export function StatusBadge({
  value,
  tone,
  className = "",
}: {
  value: string;
  tone?: StatusTone;
  className?: string;
}) {
  const resolved: StatusTone =
    tone ??
    (() => {
      const v = value.toLowerCase();
      if (v.includes("complete") || v.includes("verified") || v.includes("active") || v.includes("analyzed") || v.includes("open")) return "verified";
      if (v.includes("fail") || v.includes("error") || v.includes("critical")) return "failed";
      if (v.includes("running") || v.includes("pending") || v.includes("unknown")) return "pending";
      return "neutral";
    })();

  const toneClass: Record<StatusTone, string> = {
    verified: "border-status-verified/30 bg-status-verified/10 text-status-verified",
    pending:  "border-status-pending/30 bg-status-pending/10 text-status-pending",
    failed:   "border-status-failed/30 bg-status-failed/10 text-status-failed",
    neutral:  "border-edge bg-surface-overlay text-content-muted",
  };

  return (
    <span
      className={[
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium",
        toneClass[resolved],
        className,
      ].join(" ")}
    >
      <span
        className={[
          "h-1.5 w-1.5 rounded-full",
          resolved === "verified" ? "bg-status-verified"
          : resolved === "pending" ? "bg-status-pending"
          : resolved === "failed"  ? "bg-status-failed"
          : "bg-content-subtle",
        ].join(" ")}
      />
      {humanize(value)}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Metric                                                              */
/* ------------------------------------------------------------------ */
export function MetricCard({
  label,
  value,
  description,
  icon,
  className = "",
}: {
  label: string;
  value: number | string;
  description?: string;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={[
        "group relative overflow-hidden rounded-xl border border-edge",
        "bg-surface-subtle/60 backdrop-blur-sm",
        "p-4",
        "transition duration-[160ms] ease-[cubic-bezier(0.22,1,0.36,1)]",
        "hover:-translate-y-[1px]",
        "hover:border-[color-mix(in_oklab,var(--color-accent)_28%,var(--color-edge))]",
        "hover:shadow-[0_12px_32px_-18px_color-mix(in_oklab,var(--color-accent)_55%,transparent)]",
        className,
      ].join(" ")}
    >
      {/* soft accent corner glow */}
      <span
        aria-hidden
        className="pointer-events-none absolute -right-8 -top-8 h-24 w-24 rounded-full opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{
          background:
            "radial-gradient(circle, color-mix(in oklab, var(--color-accent) 35%, transparent), transparent 70%)",
        }}
      />
      <div className="relative flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-content-subtle">
            {label}
          </p>
          <p className="mt-3 truncate text-2xl font-semibold tabular-nums text-content">
            {value}
          </p>
          {description && (
            <p className="mt-1 truncate text-xs text-content-subtle">{description}</p>
          )}
        </div>
        {icon && (
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-overlay text-content-muted transition group-hover:text-accent">
            {icon}
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* States                                                              */
/* ------------------------------------------------------------------ */

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex min-h-56 flex-col items-center justify-center px-6 py-12 text-center">
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-edge bg-surface-overlay text-content-subtle">
        <FileSearch className="h-5 w-5" />
      </div>
      <h3 className="text-sm font-semibold text-content">{title}</h3>
      <p className="mt-2 max-w-md text-sm leading-6 text-content-subtle">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex min-h-64 flex-col items-center justify-center gap-3 text-sm text-content-muted">
      <Loader2 className="h-5 w-5 animate-spin text-accent" />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({
  title = "Something went wrong",
  description,
  onRetry,
}: {
  title?: string;
  description: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex min-h-56 flex-col items-center justify-center px-6 py-12 text-center">
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-severity-critical/30 bg-severity-critical/10 text-severity-critical">
        <AlertTriangle className="h-5 w-5" />
      </div>
      <h3 className="text-sm font-semibold text-content">{title}</h3>
      <p className="mt-2 max-w-md text-sm leading-6 text-content-muted">{description}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-4 inline-flex h-9 items-center gap-2 rounded-lg border border-edge bg-surface-subtle px-3 text-xs font-medium text-content-muted transition hover:border-edge-strong hover:text-content"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </button>
      )}
    </div>
  );
}

export function InlineCheck({ ok }: { ok: boolean }) {
  return ok ? (
    <CheckCircle2 className="h-4 w-4 text-status-verified" />
  ) : (
    <Clock className="h-4 w-4 text-content-subtle" />
  );
}