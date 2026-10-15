"use client";

import { useState } from "react";

import {
  analyzeIOCs,
  getIOCs,
  type IOC,
} from "@/lib/api";

type Props = {
  caseId: string;
  evidenceId: string;
};

export default function IOCPanel({
  caseId,
  evidenceId,
}: Props) {
  const [rows, setRows] = useState<IOC[]>([]);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);

    try {
      setRows(
        await getIOCs(
          caseId,
          evidenceId,
          {
            limit: 500,
          }
        )
      );
    } finally {
      setLoading(false);
    }
  }

  async function analyze() {
    setLoading(true);

    try {
      await analyzeIOCs(
        caseId,
        evidenceId
      );

      await load();
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-500">
            Phase 8
          </p>

          <h2 className="mt-1 text-2xl font-semibold">
            IOC Intelligence
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Indicators extracted from network evidence.
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
            className="rounded-lg bg-cyan-600 px-4 py-2 text-sm text-white"
          >
            {loading
              ? "Extracting..."
              : "Extract IOCs"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        {[
          "IP",
          "DOMAIN",
          "URL",
          "USER_AGENT",
          "OTHER",
        ].map((type) => (
          <div
            key={type}
            className="rounded-xl border bg-white p-4 dark:bg-zinc-950"
          >
            <p className="text-xs text-zinc-500">
              {type}
            </p>

            <p className="mt-2 text-2xl font-semibold">
              {
                rows.filter(
                  (row) =>
                    row.ioc_type === type
                ).length
              }
            </p>
          </div>
        ))}
      </div>

      <div className="overflow-hidden rounded-xl border">
        {rows.length === 0 ? (
          <div className="p-12 text-center">
            <p className="font-medium">
              No IOCs extracted
            </p>

            <p className="mt-2 text-sm text-zinc-500">
              Run IOC extraction against the analyzed
              evidence.
            </p>
          </div>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="border-b bg-zinc-50 dark:bg-zinc-900">
              <tr>
                <th className="px-4 py-3">
                  Type
                </th>
                <th className="px-4 py-3">
                  Value
                </th>
                <th className="px-4 py-3">
                  Source
                </th>
                <th className="px-4 py-3">
                  Occurrences
                </th>
                <th className="px-4 py-3">
                  Confidence
                </th>
              </tr>
            </thead>

            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  className="border-b"
                >
                  <td className="px-4 py-3">
                    {row.ioc_type}
                  </td>

                  <td className="px-4 py-3 font-mono text-xs">
                    {row.value}
                  </td>

                  <td className="px-4 py-3">
                    {row.source}
                  </td>

                  <td className="px-4 py-3">
                    {row.occurrences}
                  </td>

                  <td className="px-4 py-3">
                    {Math.round(
                      row.confidence * 100
                    )}
                    %
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}