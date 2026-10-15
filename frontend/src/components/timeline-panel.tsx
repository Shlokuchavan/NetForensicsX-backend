"use client";

import { useState } from "react";

import {
  buildTimeline,
  getTimeline,
  type TimelineEvent,
} from "@/lib/api";

type Props = {
  caseId: string;
  evidenceId: string;
};

function formatTimestamp(
  timestamp: number
) {
  return new Date(
    timestamp * 1000
  ).toLocaleString();
}

export default function TimelinePanel({
  caseId,
  evidenceId,
}: Props) {
  const [events, setEvents] =
    useState<TimelineEvent[]>([]);

  const [loading, setLoading] =
    useState(false);

  async function load() {
    setLoading(true);

    try {
      setEvents(
        await getTimeline(
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

  async function build() {
    setLoading(true);

    try {
      await buildTimeline(
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
            Phase 9
          </p>

          <h2 className="mt-1 text-2xl font-semibold">
            Forensic Timeline
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Unified chronological view of network activity.
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
            onClick={build}
            disabled={loading}
            className="rounded-lg bg-cyan-600 px-4 py-2 text-sm text-white"
          >
            {loading
              ? "Building..."
              : "Build Timeline"}
          </button>
        </div>
      </div>

      {events.length === 0 ? (
        <div className="rounded-xl border p-12 text-center">
          <p className="font-medium">
            Timeline not built
          </p>

          <p className="mt-2 text-sm text-zinc-500">
            Build the timeline after protocol and
            detection analysis.
          </p>
        </div>
      ) : (
        <div className="relative ml-4 border-l">
          {events.map((event) => (
            <div
              key={event.id}
              className="relative pb-8 pl-8"
            >
              <div className="absolute -left-[5px] top-1 h-2.5 w-2.5 rounded-full bg-cyan-500" />

              <div className="rounded-xl border bg-white p-4 dark:bg-zinc-950">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xs font-mono text-zinc-500">
                    {formatTimestamp(
                      event.timestamp
                    )}
                  </span>

                  <span className="rounded-full border px-2 py-1 text-[10px] uppercase">
                    {event.event_type}
                  </span>

                  <span className="rounded-full border px-2 py-1 text-[10px] uppercase">
                    {event.severity}
                  </span>
                </div>

                <h3 className="mt-3 font-medium">
                  {event.title}
                </h3>

                <p className="mt-1 text-sm text-zinc-500">
                  {event.description}
                </p>

                {(event.source_ip ||
                  event.destination_ip) && (
                  <div className="mt-3 font-mono text-xs text-zinc-500">
                    {event.source_ip ?? "—"}
                    {" → "}
                    {event.destination_ip ?? "—"}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}