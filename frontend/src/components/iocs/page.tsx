import Link from "next/link";
import { Fingerprint, ArrowRight } from "lucide-react";

export const metadata = { title: "Indicators of Compromise" };

export default function IOCsPage() {
  return (
    <div className="mx-auto w-full max-w-[1000px] p-5 md:p-7">
      <div className="mb-6">
        <div className="mb-2 inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-accent">
          <Fingerprint className="size-3.5" />
          Threat analysis
        </div>
        <h1 className="text-3xl font-semibold tracking-tight text-content">
          Indicators of Compromise
        </h1>
        <p className="mt-2 max-w-2xl text-sm text-content-muted">
          Cross-case indicator analysis is not yet implemented. Indicators are
          currently extracted and reviewed per evidence file inside each case.
        </p>
      </div>

      <div className="rounded-2xl border border-dashed border-edge bg-surface-raised/60 p-10 text-center backdrop-blur-md">
        <div className="mx-auto flex size-12 items-center justify-center rounded-xl bg-surface-overlay text-content-subtle">
          <Fingerprint className="size-5" />
        </div>
        <h2 className="mt-4 text-sm font-semibold text-content">
          Open a case to review its indicators
        </h2>
        <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-content-subtle">
          IOCs are produced by the backend per evidence file. Aggregating them
          across an entire case or workspace would require a new backend
          endpoint that does not exist today.
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