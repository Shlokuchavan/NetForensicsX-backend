"use client";

import { useState } from "react";

import {
  analyzeDetections,
  getDetectionSummary,
  getDetections,
  type Detection,
  type DetectionSummary,
} from "@/lib/api";

type Props = {
  caseId: string;
  evidenceId: string;
};

export default function DetectionsPanel({
  caseId,
  evidenceId,
}: Props) {
  const [rows, setRows] = useState<Detection[]>([]);
  const [summary, setSummary] =
    useState<DetectionSummary | null>(null);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);

    try {
      const [
        detectionRows,
        detectionSummary,
      ] = await Promise.all([
        getDetections(
          caseId,
          evidenceId,
          {
            limit: 200,
          }
        ),
        getDetectionSummary(
          caseId,
          evidenceId
        ),
      ]);

      setRows(detectionRows);
      setSummary(detectionSummary);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load detections"
      );
    } finally {
      setLoading(false);
    }
  }

  async function analyze() {
    setLoading(true);
    setError(null);

    try {
      await analyzeDetections(
        caseId,
        evidenceId
      );

      await load();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Detection analysis failed"
      );
      setLoading(false);
    }
  }

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-500">
            Phase 7
          </p>

          <h2 className="mt-1 text-2xl font-semibold">
            Detection Center
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Behavioral detections generated from
            network forensic evidence.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={load}
            className="rounded-lg border px-4 py-2 text-sm"
          >
            Refresh
          </button>

          <button
            onClick={analyze}
            disabled={loading}
            className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            {loading
              ? "Analyzing..."
              : "Analyze Evidence"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-6">
        {[
          ["Total", summary?.total ?? 0],
          ["Critical", summary?.critical ?? 0],
          ["High", summary?.high ?? 0],
          ["Medium", summary?.medium ?? 0],
          ["Low", summary?.low ?? 0],
          ["Info", summary?.info ?? 0],
        ].map(([label, value]) => (
          <div
            key={String(label)}
            className="rounded-xl border bg-white p-4 dark:bg-zinc-950"
          >
            <p className="text-xs uppercase tracking-wider text-zinc-500">
              {label}
            </p>

            <p className="mt-2 text-2xl font-semibold">
              {value}
            </p>
          </div>
        ))}
      </div>

      <div className="overflow-hidden rounded-xl border bg-white dark:bg-zinc-950">
        {rows.length === 0 ? (
          <div className="p-12 text-center">
            <p className="font-medium">
              No detections
            </p>

            <p className="mt-2 text-sm text-zinc-500">
              Run detection analysis to identify
              suspicious network behavior.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b bg-zinc-50 dark:bg-zinc-900">
                <tr>
                  <th className="px-4 py-3">
                    Severity
                  </th>
                  <th className="px-4 py-3">
                    Detection
                  </th>
                  <th className="px-4 py-3">
                    Source
                  </th>
                  <th className="px-4 py-3">
                    Destination
                  </th>
                  <th className="px-4 py-3">
                    Confidence
                  </th>
                  <th className="px-4 py-3">
                    Status
                  </th>
                </tr>
              </thead>

              <tbody>
                {rows.map((row) => (
                  <tr
                    key={row.id}
                    className="border-b last:border-0"
                  >
                    <td className="px-4 py-3">
                      <span className="rounded-full border px-2 py-1 text-xs uppercase">
                        {row.severity}
                      </span>
                    </td>

                    <td className="px-4 py-3">
                      <div className="font-medium">
                        {row.title}
                      </div>

                      <div className="mt-1 max-w-md truncate text-xs text-zinc-500">
                        {row.description}
                      </div>
                    </td>

                    <td className="px-4 py-3 font-mono text-xs">
                      {row.source_ip ?? "—"}
                    </td>

                    <td className="px-4 py-3 font-mono text-xs">
                      {row.destination_ip ?? "—"}
                      {row.destination_port
                        ? `:${row.destination_port}`
                        : ""}
                    </td>

                    <td className="px-4 py-3">
                      {Math.round(
                        row.confidence * 100
                      )}
                      %
                    </td>

                    <td className="px-4 py-3 uppercase text-xs">
                      {row.status}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}