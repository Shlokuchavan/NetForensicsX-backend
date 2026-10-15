"use client";

import { Moon, Sun } from "lucide-react";
import { useTheme } from "@/components/theme-provider";

type Props = {
  variant?: "icon" | "labeled";
  className?: string;
};

export function ThemeToggle({ variant = "labeled", className = "" }: Props) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";
  const label = isDark ? "Switch to light theme" : "Switch to dark theme";

  if (variant === "icon") {
    return (
      <button
        type="button"
        onClick={toggleTheme}
        aria-label={label}
        title={label}
        className={[
          "inline-flex h-9 w-9 items-center justify-center rounded-lg",
          "border border-edge bg-surface-subtle text-content-muted",
          "transition duration-[120ms] ease-[cubic-bezier(0.22,1,0.36,1)]",
          "hover:border-edge-strong hover:text-content",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
          className,
        ].join(" ")}
      >
        {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={label}
      className={[
        "group inline-flex h-9 items-center gap-2 rounded-lg",
        "border border-edge bg-surface-subtle px-3",
        "text-xs font-medium text-content-muted",
        "transition duration-[120ms] ease-[cubic-bezier(0.22,1,0.36,1)]",
        "hover:border-edge-strong hover:text-content",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
        className,
      ].join(" ")}
    >
      {isDark ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
      <span className="hidden sm:inline">{isDark ? "Light" : "Dark"}</span>
    </button>
  );
}