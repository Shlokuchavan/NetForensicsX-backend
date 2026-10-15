"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  ArrowUpRight,
  FolderKanban,
  Loader2,
  Plus,
  RefreshCw,
  ShieldAlert,
  Upload,
  X,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { createCase, getCases, type Case } from "@/lib/api";
import { useSearch } from "@/components/SearchContext";

/* =========================================================
   Helpers
   ========================================================= */

function isOpen(item: Case): boolean {
  return item.status.toLowerCase() !== "closed";
}

function severityCount(cases: Case[], levels: string[]): number {
  const wanted = new Set(levels.map((l) => l.toLowerCase()));
  return cases.filter((c) => wanted.has(c.severity.toLowerCase())).length;
}

function relativeTime(value: string | null | undefined): string {
  if (!value) return "—";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "—";
  const diff = Date.now() - then;
  const sec = Math.max(1, Math.floor(diff / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  const mo = Math.floor(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

/* =========================================================
   Severity ring — animated SVG, no dependency
   ========================================================= */

function SeverityRing({
  data,
}: {
  data: { label: string; value: number; color: string }[];
}) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const radius = 52;
  const stroke = 12;
  const circumference = 2 * Math.PI * radius;
  let cumulative = 0;

  return (
    <div className="flex flex-col items-center gap-5 sm:flex-row sm:items-center sm:gap-7">
      <div className="relative shrink-0">
        <svg viewBox="0 0 130 130" className="size-[130px] -rotate-90">
          <circle
            cx="65"
            cy="65"
            r={radius}
            fill="none"
            stroke="var(--color-edge)"
            strokeWidth={stroke}
            opacity={0.6}
          />
          {total > 0 &&
            data.map((item) => {
              if (item.value === 0) return null;
              const length = (item.value / total) * circumference;
              const dash = `${length} ${circumference - length}`;
              const offset = -cumulative;
              cumulative += length;
              return (
                <circle
                  key={item.label}
                  cx="65"
                  cy="65"
                  r={radius}
                  fill="none"
                  stroke={item.color}
                  strokeWidth={stroke}
                  strokeDasharray={dash}
                  strokeDashoffset={offset}
                  strokeLinecap="butt"
                  style={{
                    transition:
                      "stroke-dasharray 600ms cubic-bezier(0.22,1,0.36,1), stroke-dashoffset 600ms cubic-bezier(0.22,1,0.36,1)",
                  }}
                />
              );
            })}
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums text-content">
            {total}
          </span>
          <span className="text-[10px] uppercase tracking-[0.14em] text-content-subtle">
            open
          </span>
        </div>
      </div>

      <ul className="flex w-full min-w-0 flex-col gap-2.5">
        {data.map((item) => (
          <li
            key={item.label}
            className="flex items-center gap-3 text-[12px]"
          >
            <span
              aria-hidden
              className="size-2 shrink-0 rounded-full"
              style={{ background: item.color }}
            />
            <span className="truncate text-content-muted">{item.label}</span>
            <span className="ml-auto tabular-nums text-content">
              {item.value}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* =========================================================
   Status bar — segmented, animated width
   ========================================================= */

function StatusBar({
  data,
}: {
  data: { label: string; value: number; color: string }[];
}) {
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <div className="space-y-5">
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-surface-overlay">
        {total === 0 ? null : (
          data.map((item) => {
            if (item.value === 0) return null;
            return (
              <span
                key={item.label}
                className="h-full transition-[width] duration-500 ease-[cubic-bezier(0.22,1,0.36,1)]"
                style={{
                  width: `${(item.value / total) * 100}%`,
                  background: item.color,
                }}
                title={`${item.label}: ${item.value}`}
              />
            );
          })
        )}
      </div>

      <ul className="flex flex-wrap gap-x-6 gap-y-2">
        {data.map((item) => (
          <li
            key={item.label}
            className="flex items-center gap-2 text-[11px]"
          >
            <span
              aria-hidden
              className="size-2 shrink-0 rounded-full"
              style={{ background: item.color }}
            />
            <span className="capitalize text-content-muted">
              {item.label}
            </span>
            <span className="tabular-nums text-content">{item.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* =========================================================
   Dashboard
   ========================================================= */

export function Dashboard() {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [creating, setCreating] = useState(false);
  const [showCreateCase, setShowCreateCase] = useState(false);
  const [caseName, setCaseName] = useState("");
  const [caseDescription, setCaseDescription] = useState("");
  const [caseSeverity, setCaseSeverity] = useState("medium");

  const { setVisible } = useSearch();

  useEffect(() => {
    setVisible(true);
    return () => setVisible(false);
  }, [setVisible]);

  async function refresh() {
    try {
      setLoading(true);
      setError(null);
      const data = await getCases();
      setCases(data);
    } catch {
      setError("API unavailable. Start Docker Compose and refresh this page.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  /* ---------------------------------------------------- */
  /* Create-case handlers                                 */
  /* ---------------------------------------------------- */

  function openCreateCase() {
    setCaseName("");
    setCaseDescription("");
    setCaseSeverity("medium");
    setError(null);
    setShowCreateCase(true);
  }

  function closeCreateCase() {
    if (!creating) setShowCreateCase(false);
  }

  async function handleCreateCase() {
    if (!caseName.trim()) {
      setError("Case name is required.");
      return;
    }
    try {
      setCreating(true);
      setError(null);
      const created = await createCase({
        name: caseName.trim(),
        description: caseDescription.trim() || undefined,
        severity: caseSeverity,
      });
      setCases((current) => [created, ...current]);
      setShowCreateCase(false);
      setCaseName("");
      setCaseDescription("");
      setCaseSeverity("medium");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not create the case."
      );
    } finally {
      setCreating(false);
    }
  }

  /* ---------------------------------------------------- */
  /* Derived analytics                                    */
  /* ---------------------------------------------------- */

  const openCases = useMemo(() => cases.filter(isOpen), [cases]);
  const closedCases = useMemo(
    () => cases.filter((c) => c.status.toLowerCase() === "closed"),
    [cases]
  );

  const highRiskOpen = useMemo(
    () => severityCount(openCases, ["critical", "high"]),
    [openCases]
  );

  const thisMonth = useMemo(() => {
    const now = new Date();
    const startOfMonth = new Date(
      now.getFullYear(),
      now.getMonth(),
      1
    ).getTime();
    return cases.filter((c) => {
      const t = new Date(c.created_at).getTime();
      return Number.isFinite(t) && t >= startOfMonth;
    }).length;
  }, [cases]);

  const severityDistribution = useMemo(
    () => [
      {
        label: "Critical",
        value: severityCount(openCases, ["critical"]),
        color: "var(--color-severity-critical)",
      },
      {
        label: "High",
        value: severityCount(openCases, ["high"]),
        color: "var(--color-severity-high)",
      },
      {
        label: "Medium",
        value: severityCount(openCases, ["medium"]),
        color: "var(--color-severity-medium)",
      },
      {
        label: "Low",
        value: severityCount(openCases, ["low"]),
        color: "var(--color-severity-low)",
      },
    ],
    [openCases]
  );

  const statusDistribution = useMemo(() => {
    const distinct = new Set<string>();
    cases.forEach((c) => distinct.add(c.status.toLowerCase()));

    const palette: Record<string, string> = {
      open: "var(--color-accent)",
      in_progress: "var(--color-status-pending)",
      under_review: "var(--color-atmos-violet)",
      closed: "var(--color-status-verified)",
    };

    const fallback = [
      "var(--color-atmos-amber)",
      "var(--color-content-subtle)",
      "var(--color-severity-low)",
    ];
    let fi = 0;

    return Array.from(distinct).map((status) => {
      const color = palette[status] ?? fallback[fi++ % fallback.length];
      return {
        label: status.replace(/_/g, " "),
        value: cases.filter((c) => c.status.toLowerCase() === status)
          .length,
        color,
      };
    });
  }, [cases]);

  const recentCases = useMemo(
    () =>
      [...cases]
        .sort(
          (a, b) =>
            new Date(b.updated_at ?? b.created_at).getTime() -
            new Date(a.updated_at ?? a.created_at).getTime()
        )
        .slice(0, 6),
    [cases]
  );

  /* ---------------------------------------------------- */
  /* Render                                               */
  /* ---------------------------------------------------- */

  return (
    <div className="mx-auto w-full max-w-[1400px] px-5 py-8 md:px-8">
      {/* Header */}
      <header className="mb-8 flex flex-col justify-between gap-5 md:flex-row md:items-end">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-content-subtle">
            Workspace · Overview
          </p>
          <h1 className="mt-3 text-[32px] font-semibold leading-tight tracking-[-0.02em] text-content md:text-[38px]">
            Investigation summary
          </h1>
          <p className="mt-2 max-w-xl text-[13px] leading-6 text-content-muted">
            Snapshot of every case stored on this platform. Deeper metrics
            live inside each investigation.
          </p>
        </div>

        <div className="flex shrink-0 gap-2">
          <Link href="/cases">
            <Button
              variant="outline"
              className="h-10 border-edge bg-surface-raised/50 text-content-muted hover:border-edge-strong hover:text-content"
            >
              <Upload className="size-4" />
              Upload evidence
            </Button>
          </Link>

          <Button
            onClick={openCreateCase}
            className="h-10 bg-accent text-accent-foreground transition hover:bg-accent-muted"
          >
            <Plus className="size-4" />
            New case
          </Button>

          <Button
            variant="outline"
            onClick={() => void refresh()}
            disabled={loading}
            className="h-10 border-edge bg-surface-raised/50 text-content-muted hover:border-edge-strong hover:text-content"
          >
            <RefreshCw
              className={`size-4 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
        </div>
      </header>

      {error && (
        <div
          role="alert"
          className="mb-6 rounded-xl border border-severity-critical/30 bg-severity-critical/10 px-4 py-3 text-[13px] text-severity-critical backdrop-blur"
        >
          {error}
        </div>
      )}

      {/* Hero + Stat rail */}
      <section className="grid gap-4 lg:grid-cols-[1.7fr_1fr]">
        {/* Hero panel */}
        <div className="group relative overflow-hidden rounded-[24px] border border-edge/70 bg-surface-raised/50 backdrop-blur-md transition hover:border-accent/30">
          <span
            aria-hidden
            className="pointer-events-none absolute inset-x-0 top-0 h-[2px]"
            style={{
              background:
                "linear-gradient(90deg, transparent, var(--color-accent), transparent)",
              backgroundSize: "200% 100%",
              animation: "nfx-hero-drift 8s linear infinite",
            }}
          />

          <div className="p-7 sm:p-8">
            <div className="flex items-baseline gap-4">
              <span className="text-[64px] font-semibold leading-none tracking-[-0.04em] tabular-nums text-content sm:text-[76px]">
                {loading ? "—" : openCases.length}
              </span>
              <div className="pb-2">
                <p className="text-[13px] font-medium text-content">
                  open case{openCases.length === 1 ? "" : "s"}
                </p>
                <p className="mt-0.5 text-[11px] text-content-subtle">
                  {closedCases.length} closed · {cases.length} total
                </p>
              </div>
            </div>

            <p className="mt-6 max-w-md text-[12.5px] leading-6 text-content-muted">
              Open investigations currently tracked. Open any case to
              inspect its evidence, network flows, detections, and
              timeline.
            </p>

            <div className="mt-6 flex flex-wrap gap-2">
              <Link
                href="/cases"
                className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-edge bg-surface-subtle px-3 text-[12px] font-medium text-content-muted transition hover:border-edge-strong hover:text-content"
              >
                Open cases
                <ArrowRight className="size-3.5" />
              </Link>
              <Link
                href="/closed"
                className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-edge bg-surface-subtle px-3 text-[12px] font-medium text-content-muted transition hover:border-edge-strong hover:text-content"
              >
                View archive
                <ArrowRight className="size-3.5" />
              </Link>
            </div>
          </div>

          <div className="border-t border-edge/60 bg-surface/30 px-7 py-5 sm:px-8">
            <div className="mb-3 flex items-center justify-between">
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-subtle">
                Status distribution
              </p>
              <p className="text-[10px] tabular-nums text-content-subtle">
                {cases.length} total
              </p>
            </div>
            {loading ? (
              <div className="flex h-10 items-center text-[12px] text-content-subtle">
                <Loader2 className="mr-2 size-3.5 animate-spin text-accent" />
                Loading…
              </div>
            ) : cases.length === 0 ? (
              <p className="text-[12px] text-content-subtle">
                No cases recorded yet.
              </p>
            ) : (
              <StatusBar data={statusDistribution} />
            )}
          </div>
        </div>

        {/* Stat rail */}
        <div className="flex flex-col gap-4">
          <CompactStat
            label="High-risk open"
            value={highRiskOpen}
            hint="Critical + high severity"
            accent="var(--color-severity-high)"
            icon={ShieldAlert}
            href="/cases"
            loading={loading}
          />
          <CompactStat
            label="Created this month"
            value={thisMonth}
            hint="Since the 1st"
            accent="var(--color-atmos-violet)"
            icon={FolderKanban}
            href="/cases"
            loading={loading}
          />
          <CompactStat
            label="Closed archive"
            value={closedCases.length}
            hint="Resolved investigations"
            accent="var(--color-status-verified)"
            icon={ArrowUpRight}
            href="/closed"
            loading={loading}
          />
        </div>
      </section>

      {/* Severity + recent */}
      <section className="mt-4 grid gap-4 lg:grid-cols-[1fr_1.7fr]">
        <div className="rounded-[24px] border border-edge/70 bg-surface-raised/50 p-7 backdrop-blur-md sm:p-8">
          <div className="mb-6 flex items-start justify-between">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-subtle">
                Severity profile
              </p>
              <p className="mt-2 text-[13px] leading-6 text-content-muted">
                Distribution across open cases only.
              </p>
            </div>
          </div>

          {loading ? (
            <div className="flex h-40 items-center justify-center text-[12px] text-content-subtle">
              <Loader2 className="mr-2 size-3.5 animate-spin text-accent" />
              Loading…
            </div>
          ) : openCases.length === 0 ? (
            <div className="flex h-40 flex-col items-center justify-center text-center">
              <ShieldAlert className="size-5 text-content-subtle" />
              <p className="mt-3 text-[12px] text-content-subtle">
                No open cases to profile.
              </p>
            </div>
          ) : (
            <SeverityRing data={severityDistribution} />
          )}
        </div>

        <div className="rounded-[24px] border border-edge/70 bg-surface-raised/50 backdrop-blur-md">
          <div className="flex items-center justify-between border-b border-edge/60 px-7 py-5 sm:px-8">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-subtle">
                Recently updated
              </p>
              <p className="mt-2 text-[13px] text-content-muted">
                Latest activity across all cases.
              </p>
            </div>
            <Link
              href="/cases"
              className="inline-flex items-center gap-1 text-[11px] font-medium text-content-muted transition hover:text-accent"
            >
              View all
              <ArrowRight className="size-3" />
            </Link>
          </div>

          {loading ? (
            <div className="flex items-center justify-center gap-2 py-14 text-[12px] text-content-subtle">
              <Loader2 className="size-3.5 animate-spin text-accent" />
              Loading…
            </div>
          ) : recentCases.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-14 text-center">
              <p className="text-[12px] text-content-subtle">
                No cases recorded yet.
              </p>
              <Button
                size="sm"
                onClick={openCreateCase}
                className="h-8 bg-accent text-accent-foreground hover:bg-accent-muted"
              >
                <Plus className="size-3.5" />
                Create case
              </Button>
            </div>
          ) : (
            <ul className="divide-y divide-edge/60">
              {recentCases.map((item) => (
                <li key={item.id}>
                  <Link
                    href={`/cases/${item.id}`}
                    className="group flex items-center gap-4 px-7 py-4 transition hover:bg-surface-overlay/30 sm:px-8"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <p className="truncate text-[13.5px] font-medium text-content">
                          {item.name}
                        </p>
                        <span className="hidden shrink-0 rounded-md border border-edge/70 bg-surface/60 px-1.5 py-0.5 font-mono text-[10px] text-content-subtle sm:inline">
                          {item.case_number}
                        </span>
                      </div>
                      <div className="mt-1 flex items-center gap-3 text-[11px] text-content-subtle">
                        <span className="capitalize">
                          {item.status.replace(/_/g, " ")}
                        </span>
                        <span aria-hidden>·</span>
                        <span className="capitalize">{item.severity}</span>
                        <span aria-hidden>·</span>
                        <span>
                          {relativeTime(item.updated_at ?? item.created_at)}
                        </span>
                      </div>
                    </div>
                    <ArrowUpRight className="size-4 shrink-0 text-content-subtle transition-transform duration-150 group-hover:-translate-y-[1px] group-hover:translate-x-[1px] group-hover:text-accent" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <p className="mt-8 text-center text-[11px] text-content-subtle">
        Per-evidence analytics, detection trends, and IOC rollups become
        available inside each investigation.
      </p>

      {/* ------------------------------------------------ */}
      {/* Create-case modal                                */}
      {/* ------------------------------------------------ */}
      {showCreateCase && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-md"
          onMouseDown={closeCreateCase}
        >
          <div
            className="w-full max-w-lg overflow-hidden rounded-2xl border border-edge bg-surface-raised/95 shadow-[0_24px_64px_-32px_rgb(0_0_0_/_0.6)] backdrop-blur-xl"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <span
              aria-hidden
              className="block h-px w-full"
              style={{
                background:
                  "linear-gradient(to right, transparent, color-mix(in oklab, var(--color-accent) 60%, transparent), transparent)",
              }}
            />

            <div className="p-6">
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-xl font-semibold text-content">
                    Create new investigation
                  </h2>
                  <p className="mt-1 text-sm text-content-muted">
                    Define the investigation before adding network evidence.
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={closeCreateCase}
                  disabled={creating}
                  className="text-content-muted hover:text-content"
                >
                  <X className="size-4" />
                </Button>
              </div>

              <div className="mt-6 space-y-5">
                <div>
                  <label className="text-sm font-medium text-content">
                    Case name
                  </label>
                  <input
                    value={caseName}
                    onChange={(event) => setCaseName(event.target.value)}
                    placeholder="e.g. Suspicious Internal Traffic"
                    className="mt-2 flex h-10 w-full rounded-lg border border-edge bg-surface px-3 text-sm text-content outline-none transition placeholder:text-content-subtle focus:border-accent focus:ring-2 focus:ring-accent/20"
                    autoFocus
                  />
                </div>

                <div>
                  <label className="text-sm font-medium text-content">
                    Description
                  </label>
                  <textarea
                    value={caseDescription}
                    onChange={(event) =>
                      setCaseDescription(event.target.value)
                    }
                    placeholder="Describe the purpose or scope of this investigation..."
                    rows={4}
                    className="mt-2 w-full resize-none rounded-lg border border-edge bg-surface px-3 py-2 text-sm text-content outline-none transition placeholder:text-content-subtle focus:border-accent focus:ring-2 focus:ring-accent/20"
                  />
                </div>

                <div>
                  <label className="text-sm font-medium text-content">
                    Severity
                  </label>
                  <select
                    value={caseSeverity}
                    onChange={(event) =>
                      setCaseSeverity(event.target.value)
                    }
                    className="mt-2 h-10 w-full rounded-lg border border-edge bg-surface px-3 text-sm text-content outline-none focus:border-accent"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button
                    variant="outline"
                    onClick={closeCreateCase}
                    disabled={creating}
                    className="border-edge"
                  >
                    Cancel
                  </Button>
                  <Button
                    onClick={() => void handleCreateCase()}
                    disabled={creating || !caseName.trim()}
                    className="bg-accent text-accent-foreground hover:bg-accent-muted"
                  >
                    <Plus className="size-4" />
                    {creating ? "Creating…" : "Create case"}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* =========================================================
   Compact stat tile
   ========================================================= */

function CompactStat({
  label,
  value,
  hint,
  accent,
  icon: Icon,
  href,
  loading,
}: {
  label: string;
  value: number;
  hint: string;
  accent: string;
  icon: React.ElementType;
  href: string;
  loading: boolean;
}) {
  return (
    <Link
      href={href}
      className="group relative flex flex-1 items-center gap-4 overflow-hidden rounded-[20px] border border-edge/70 bg-surface-raised/50 p-5 backdrop-blur-md transition duration-200 hover:-translate-y-[2px] hover:border-accent/30"
    >
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{
          background: `radial-gradient(circle at 20% 120%, color-mix(in oklab, ${accent} 22%, transparent), transparent 65%)`,
        }}
      />

      <span
        className="relative flex size-10 shrink-0 items-center justify-center rounded-[12px]"
        style={{
          background: `color-mix(in oklab, ${accent} 12%, transparent)`,
          color: accent,
        }}
      >
        <Icon className="size-4" />
      </span>

      <div className="relative min-w-0 flex-1">
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-subtle">
          {label}
        </p>
        <p className="mt-1 text-2xl font-semibold leading-none tabular-nums text-content">
          {loading ? "—" : value}
        </p>
        <p className="mt-1.5 truncate text-[11px] text-content-subtle">
          {hint}
        </p>
      </div>

      <ArrowUpRight className="relative size-4 shrink-0 text-content-subtle transition group-hover:text-accent" />
    </Link>
  );
}