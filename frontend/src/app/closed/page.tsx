"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Archive,
  ArrowUpRight,
  FileSearch,
  Loader2,
  RefreshCw,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { getCases, type Case } from "@/lib/api";
import { SeverityBadge, StatusBadge } from "@/components/nfx/primitives";
import { useSearch } from "@/components/SearchContext";

export default function ClosedCasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  const closed = useMemo(
    () => cases.filter((item) => item.status.toLowerCase() === "closed"),
    [cases]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return closed;
    return closed.filter(
      (item) =>
        item.name.toLowerCase().includes(q) ||
        item.case_number.toLowerCase().includes(q) ||
        (item.description ?? "").toLowerCase().includes(q)
    );
  }, [closed, query]);

  return (
    <div className="mx-auto w-full max-w-[1200px] px-5 py-7 md:px-7">
      <section className="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mb-2 inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-accent">
            <Archive className="size-3.5" />
            Archive
          </div>
          <h1 className="text-3xl font-semibold tracking-tight text-content">
            Closed cases
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-content-muted">
            {query.trim()
              ? `${filtered.length} of ${closed.length} matching "${query.trim()}"`
              : "Investigations that have been closed."}
          </p>
        </div>

        <Button
          variant="outline"
          onClick={() => void refresh()}
          className="border-edge text-content-muted hover:text-content"
        >
          <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </section>

      {error && (
        <div
          role="alert"
          className="mb-5 rounded-xl border border-severity-critical/30 bg-severity-critical/10 px-4 py-3 text-sm text-severity-critical backdrop-blur"
        >
          {error}
        </div>
      )}

      <div className="rounded-2xl border border-edge bg-surface-raised/60 backdrop-blur-md">
        {loading ? (
          <div className="flex items-center justify-center gap-3 py-16 text-sm text-content-muted">
            <Loader2 className="size-4 animate-spin text-accent" />
            Loading cases…
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <div className="flex size-12 items-center justify-center rounded-xl border border-edge bg-surface-overlay text-content-subtle">
              <Archive className="size-5" />
            </div>
            <h3 className="mt-4 text-sm font-semibold text-content">
              {closed.length === 0 ? "No closed cases" : "No matching cases"}
            </h3>
            <p className="mt-2 max-w-sm text-sm leading-6 text-content-subtle">
              {closed.length === 0
                ? "Cases with status “closed” appear here."
                : "Try a different search term."}
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
                    {item.case_number} · Closed{" "}
                    {new Date(item.updated_at).toLocaleString()}
                  </div>
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