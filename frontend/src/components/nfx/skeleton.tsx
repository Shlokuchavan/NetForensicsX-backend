export function SkeletonLine({ className = "" }: { className?: string }) {
  return (
    <div
      className={[
        "h-3 rounded-full bg-surface-overlay/70",
        "animate-pulse",
        className,
      ].join(" ")}
    />
  );
}

export function SkeletonBlock({ className = "" }: { className?: string }) {
  return (
    <div
      className={[
        "rounded-lg bg-surface-overlay/60",
        "animate-pulse",
        className,
      ].join(" ")}
    />
  );
}

export function SkeletonMetricCard() {
  return (
    <div className="rounded-lg border border-edge bg-surface-subtle/60 p-4">
      <SkeletonLine className="w-24" />
      <SkeletonBlock className="mt-4 h-8 w-20" />
      <SkeletonLine className="mt-3 w-32" />
    </div>
  );
}