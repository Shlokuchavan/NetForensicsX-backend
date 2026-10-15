"use client";

import { useState } from "react";

import {
  analyzeMitre,
  getMitreMappings,
  type MitreMapping,
} from "@/lib/api";

type Props = {
  caseId: string;
  evidenceId: string;
};

export default function MitrePanel({
  caseId,
  evidenceId,
}: Props) {
  const [rows, setRows] =
    useState<MitreMapping[]>([]);

  const [loading, setLoading] =
    useState(false);

  async function load() {
    setLoading(true);

    try {
      setRows(
        await getMitreMappings(
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
      await analyzeMitre(
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
            Phase 10
          </p>

          <h2 className="mt-1 text-2xl font-semibold">
            MITRE ATT&CK
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Behavioral detections mapped to ATT&CK techniques.
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
              ? "Mapping..."
              : "Map Techniques"}
          </button>
        </div>
      </div>

      {rows.length === 0 ? (
        <div className="rounded-xl border p-12 text-center">
          <p className="font-medium">
            No ATT&CK mappings
          </p>

          <p className="mt-2 text-sm text-zinc-500">
            Run the MITRE mapping engine after
            detection analysis.
          </p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {rows.map((row) => (
            <div
              key={row.id}
              className="rounded-xl border bg-white p-5 dark:bg-zinc-950"
            >
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-mono text-sm font-semibold text-cyan-500">
                    {row.technique_id}
                  </p>

                  <h3 className="mt-1 font-semibold">
                    {row.technique_name}
                  </h3>
                </div>

                <span className="rounded-full border px-2 py-1 text-[10px] uppercase">
                  {row.tactic}
                </span>
              </div>

              <p className="mt-4 text-sm text-zinc-500">
                {row.description}
              </p>

              <div className="mt-4 text-xs text-zinc-500">
                Confidence:{" "}
                {Math.round(
                  row.confidence * 100
                )}
                %
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}