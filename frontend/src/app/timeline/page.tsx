import Link from "next/link";
import { Clock3, ArrowRight } from "lucide-react";

export const metadata = { title: "Timeline" };

export default function TimelinePage() {
  return (
    <div className="mx-auto w-full max-w-[1000px] p-5 md:p-7">
      <div className="mb-6">
        <div className="mb-2 inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-accent">
          <Clock3 className="size-3.5" />
          Correlation
        </div>
        <h1 className="text-3xl font-semibold tracking-tight text-content">
          Investigation timeline
        </h1>
        <p className="mt-2 max-w-2xl text-sm text-content-muted">
          Cross-case timeline is not yet implemented. Timelines are built per
          evidence file inside each case.
        </p>
      </div>

      <div className="rounded-2xl border border-dashed border-edge bg-surface-raised/60 p-10 text-center backdrop-blur-md">
        <div className="mx-auto flex size-12 items-center justify-center rounded-xl bg-surface-overlay text-content-subtle">
          <Clock3 className="size-5" />
        </div>
        <h2 className="mt-4 text-sm font-semibold text-content">
          Open a case to build its timeline
        </h2>
        <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-content-subtle">
          Timeline events are produced from the evidence in each case. A
          cross-case view would need a new aggregation endpoint.
        </p>
        <Link
          href="/cases"
          className="mt-5 inline-flex h-10 items-center gap-2 rounded-lg bg-accent px-4 text-sm font-semibold text-accent-foreground transition hover:bg-accent-muted"
        >
          Go to cases
          <ArrowRight className="size-4" />
        </Link>
      </div>
    </div>
  );
}