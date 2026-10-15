"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowUpRight,
  FileSearch,
  FolderKanban,
  Loader2,
  Plus,
  RefreshCw,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { getCases, type Case } from "@/lib/api";
import { SeverityBadge, StatusBadge } from "@/components/nfx/primitives";
import { useSearch } from "@/components/SearchContext";

type StatusFilter = "all" | "open" | "in_progress" | "under_review" | "closed";
type SeverityFilter = "all" | "low" | "medium" | "high" | "critical";

export default function CasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");

  const { query, setVisible } = useSearch();

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

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();

    return cases.filter((item) => {
      const matchesSearch =
        !q ||
        item.name.toLowerCase().includes(q) ||
        item.case_number.toLowerCase().includes(q) ||
        (item.description ?? "").toLowerCase().includes(q);

      const matchesStatus =
        statusFilter === "all" ||
        item.status.toLowerCase() === statusFilter;

      const matchesSeverity =
        severityFilter === "all" ||
        item.severity.toLowerCase() === severityFilter;

      return matchesSearch && matchesStatus && matchesSeverity;
    });
  }, [cases, query, statusFilter, severityFilter]);

  return (
    <div className="mx-auto w-full max-w-[1500px] px-5 py-7 md:px-7">
      <section className="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mb-2 inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-accent">
            <FolderKanban className="size-3.5" />
            Workspace
          </div>
          <h1 className="text-3xl font-semibold tracking-tight text-content">
            All cases
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-content-muted">
            Every investigation stored in the platform.
          </p>
        </div>

        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => void refresh()}
            className="border-edge text-content-muted hover:text-content"
          >
            <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>

          <Link href="/">
            <Button className="bg-accent text-accent-foreground hover:bg-accent-muted">
              <Plus className="size-4" />
              New case
            </Button>
          </Link>
        </div>
      </section>

      {error && (
        <div
          role="alert"
          className="mb-5 rounded-xl border border-severity-critical/30 bg-severity-critical/10 px-4 py-3 text-sm text-severity-critical backdrop-blur"
        >
          {error}
        </div>
      )}

      <div className="mb-5 flex flex-wrap items-center gap-3 rounded-2xl border border-edge bg-surface-raised/60 p-4 backdrop-blur-md">
        <label className="flex items-center gap-2 text-xs text-content-muted">
          <span>Status</span>
          <select
            value={statusFilter}
            onChange={(event) =>
              setStatusFilter(event.target.value as StatusFilter)
            }
            className="h-10 rounded-lg border border-edge bg-surface px-3 text-sm text-content outline-none focus:border-accent"
          >
            <option value="all">All</option>
            <option value="open">Open</option>
            <option value="in_progress">In progress</option>
            <option value="under_review">Under review</option>
            <option value="closed">Closed</option>
          </select>
        </label>

        <label className="flex items-center gap-2 text-xs text-content-muted">
          <span>Severity</span>
          <select
            value={severityFilter}
            onChange={(event) =>
              setSeverityFilter(event.target.value as SeverityFilter)
            }
            className="h-10 rounded-lg border border-edge bg-surface px-3 text-sm text-content outline-none focus:border-accent"
          >
            <option value="all">All</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </label>

        <span className="ml-auto text-xs text-content-subtle">
          {loading ? "…" : `${filtered.length} shown`}
          {query.trim() && !loading ? ` · matching "${query.trim()}"` : ""}
        </span>
      </div>

      <div className="rounded-2xl border border-edge bg-surface-raised/60 backdrop-blur-md">
        {loading ? (
          <div className="flex items-center justify-center gap-3 py-16 text-sm text-content-muted">
            <Loader2 className="size-4 animate-spin text-accent" />
            Loading cases…
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <div className="flex size-12 items-center justify-center rounded-xl border border-edge bg-surface-overlay text-content-subtle">
              <FileSearch className="size-5" />
            </div>
            <h3 className="mt-4 text-sm font-semibold text-content">
              {cases.length === 0 ? "No cases yet" : "No matching cases"}
            </h3>
            <p className="mt-2 max-w-sm text-sm leading-6 text-content-subtle">
              {cases.length === 0
                ? "Create your first case from the Overview tab."
                : "Try clearing the search or filters."}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-edge">
            {filtered.map((item) => (
              <Link
                key={item.id}
                href={`/cases/${item.id}`}
                className="group flex flex-col gap-3 p-4 transition hover:bg-surface-overlay/40 md:flex-row md:items-center"
              >
                <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-accent/10 text-accent ring-1 ring-inset ring-accent/20">
                  <FileSearch className="size-4" />
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-content">
                      {item.name}
                    </span>
                    <StatusBadge value={item.status} />
                    <SeverityBadge value={item.severity} />
                  </div>

                  <div className="mt-1 text-xs text-content-subtle">
                    {item.case_number} · Created{" "}
                    {new Date(item.created_at).toLocaleString()}
                  </div>

                  {item.description && (
                    <p className="mt-2 line-clamp-2 max-w-3xl text-xs leading-5 text-content-muted">
                      {item.description}
                    </p>
                  )}
                </div>

                <span className="inline-flex items-center gap-1 text-xs font-medium text-content-muted transition group-hover:text-accent">
                  Open
                  <ArrowUpRight className="size-3.5" />
                </span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}