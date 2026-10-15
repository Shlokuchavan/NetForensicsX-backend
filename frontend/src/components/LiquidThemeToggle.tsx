"use client";

import { Moon, Sun } from "lucide-react";
import { useTheme } from "@/components/theme-provider";

export function LiquidThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";

  return (
    <button
      type="button"
      role="switch"
      aria-checked={isDark}
      aria-label={isDark ? "Switch to light theme" : "Switch to dark theme"}
      title={isDark ? "Switch to light theme" : "Switch to dark theme"}
      onClick={toggleTheme}
      className={[
        "group relative inline-flex h-8 w-[62px] shrink-0 items-center",
        "rounded-full border border-edge",
        "bg-surface-overlay/70 backdrop-blur",
        "shadow-[inset_0_1px_2px_rgb(0_0_0_/_0.25),inset_0_-1px_1px_color-mix(in_oklab,white_6%,transparent)]",
        "transition-colors duration-200",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
        "hover:border-edge-strong",
      ].join(" ")}
    >
      <Sun
        className={[
          "pointer-events-none absolute left-[6px] size-3.5 transition-colors duration-200",
          isDark ? "text-content-subtle/60" : "text-severity-medium",
        ].join(" ")}
      />
      <Moon
        className={[
          "pointer-events-none absolute right-[6px] size-3.5 transition-colors duration-200",
          isDark ? "text-accent" : "text-content-subtle/60",
        ].join(" ")}
      />

      <span
        aria-hidden
        className={[
          "relative z-10 inline-block size-[26px] rounded-full",
          "bg-surface-raised",
          "shadow-[0_1px_3px_rgb(0_0_0_/_0.35),inset_0_1px_0_color-mix(in_oklab,white_8%,transparent)]",
          "ring-1 ring-edge",
          "transition-transform duration-[260ms] ease-[cubic-bezier(0.22,1,0.36,1)]",
          isDark ? "translate-x-[32px]" : "translate-x-[3px]",
        ].join(" ")}
      />
    </button>
  );
}