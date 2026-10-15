"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Archive,
  Bell,
  FolderKanban,
  Info,
  Search,
  Shield,
  User,
  X,
} from "lucide-react";
import { LiquidThemeToggle } from "@/components/LiquidThemeToggle";
import { useSearch } from "@/components/SearchContext";

type Tab = {
  label: string;
  href: string;
  icon: React.ElementType;
  match: (path: string) => boolean;
};

const TABS: Tab[] = [
  { label: "About", href: "/about", icon: Info, match: (p) => p === "/about" },
  { label: "Overview", href: "/", icon: Activity, match: (p) => p === "/" },
  {
    label: "Cases",
    href: "/cases",
    icon: FolderKanban,
    match: (p) => p === "/cases" || /^\/cases\/[^/]+$/.test(p),
  },
  {
    label: "Closed",
    href: "/closed",
    icon: Archive,
    match: (p) => p === "/closed",
  },
];

function useOutsideClose<T extends HTMLElement>(
  onClose: () => void,
  isOpen: boolean
) {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    function onDown(event: MouseEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        onClose();
      }
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [isOpen, onClose]);

  return ref;
}

export function TopNav() {
  const pathname = usePathname();
  const { query, setQuery, visible } = useSearch();

  const [mobileSearchOpen, setMobileSearchOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);

  const accountRef = useOutsideClose<HTMLDivElement>(
    () => setAccountOpen(false),
    accountOpen
  );
  const notifRef = useOutsideClose<HTMLDivElement>(
    () => setNotifOpen(false),
    notifOpen
  );

  return (
    <div className="nfx-nav-shell px-4 pt-5 pb-2 sm:px-6 lg:px-8">
      <header
        className={[
          "mx-auto flex h-14 max-w-[1600px] items-center gap-3",
          "rounded-full border border-edge",
          "nfx-glass",
          "transform-gpu",
          "shadow-[0_1px_0_0_color-mix(in_oklab,white_6%,transparent)_inset,0_16px_40px_-24px_rgb(0_0_0_/_0.55)]",
          "px-3 sm:px-4",
        ].join(" ")}
      >
        {/* Brand */}
        <Link
          href="/"
          className="group flex shrink-0 items-center gap-2.5 rounded-full pr-2 transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          aria-label="NetForensicX home"
        >
          <span className="flex size-9 items-center justify-center rounded-full bg-accent/15 text-accent ring-1 ring-inset ring-accent/25 transition group-hover:bg-accent/20">
            <Shield className="size-[18px]" />
          </span>
          <span className="hidden min-w-0 flex-col leading-tight sm:flex">
            <span className="truncate text-sm font-semibold tracking-tight text-content">
              NetForensicX
            </span>
            <span className="text-[10px] uppercase tracking-[0.15em] text-content-subtle">
              Network forensics
            </span>
          </span>
        </Link>

        {/* Divider */}
        <span
          aria-hidden
          className="hidden h-6 w-px shrink-0 bg-edge sm:block"
        />

        {/* Tabs */}
        <nav
          role="tablist"
          aria-label="Primary"
          className="flex min-w-0 flex-1 items-center gap-0.5 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
        >
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const active = tab.match(pathname || "/");

            return (
              <Link
                key={tab.href}
                href={tab.href}
                role="tab"
                aria-selected={active}
                aria-current={active ? "page" : undefined}
                className={[
                  "group relative inline-flex shrink-0 items-center gap-1.5 rounded-full px-3 py-2 text-[13px] font-medium",
                  "transition-[color,background-color,box-shadow] duration-150",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
                  active
                    ? "bg-accent/10 text-accent shadow-[inset_0_0_0_1px_color-mix(in_oklab,var(--color-accent)_28%,transparent)]"
                    : "text-content-muted hover:bg-[color-mix(in_oklab,var(--color-surface-overlay)_55%,transparent)] hover:text-content",
                ].join(" ")}
              >
                <Icon className="size-3.5" />
                <span className="hidden whitespace-nowrap lg:inline">
                  {tab.label}
                </span>
              </Link>
            );
          })}
        </nav>

        {/* Right cluster */}
        <div className="flex shrink-0 items-center gap-2">
          {/* Search — right side, desktop only, visible on list pages */}
          {visible && (
            <div className="relative hidden w-[240px] lg:block xl:w-[280px]">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-content-subtle" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search cases…"
                className="h-9 w-full rounded-full border border-edge bg-surface/60 pl-9 pr-3 text-xs text-content outline-none placeholder:text-content-subtle focus:border-accent"
              />
            </div>
          )}

          {/* Mobile / tablet search toggle */}
          {visible && (
            <button
              type="button"
              aria-label="Search"
              onClick={() => setMobileSearchOpen((v) => !v)}
              className="inline-flex size-9 items-center justify-center rounded-full text-content-muted transition hover:bg-surface-overlay/60 hover:text-content lg:hidden"
            >
              {mobileSearchOpen ? (
                <X className="size-4" />
              ) : (
                <Search className="size-4" />
              )}
            </button>
          )}

          {/* Notifications */}
          <div ref={notifRef} className="relative">
            <button
              type="button"
              aria-label="Notifications"
              aria-haspopup="menu"
              aria-expanded={notifOpen}
              onClick={() => {
                setNotifOpen((v) => !v);
                setAccountOpen(false);
              }}
              className="relative inline-flex size-9 items-center justify-center rounded-full text-content-muted transition hover:bg-surface-overlay/60 hover:text-content focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <Bell className="size-4" />
            </button>

            {notifOpen && (
              <div
                role="menu"
                className="absolute right-0 mt-2 w-72 overflow-hidden rounded-2xl border border-edge bg-surface-raised/95 shadow-[0_24px_64px_-32px_rgb(0_0_0_/_0.6)] backdrop-blur-xl"
              >
                <div className="border-b border-edge px-4 py-3">
                  <p className="text-sm font-semibold text-content">
                    Notifications
                  </p>
                  <p className="mt-0.5 text-[11px] text-content-subtle">
                    Activity from your investigations
                  </p>
                </div>
                <div className="px-4 py-6 text-center">
                  <p className="text-xs text-content-muted">
                    Notification delivery is not yet implemented.
                  </p>
                  <p className="mt-1 text-[11px] text-content-subtle">
                    When it is, new case activity will appear here.
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Account */}
          <div ref={accountRef} className="relative">
            <button
              type="button"
              aria-label="Account"
              aria-haspopup="menu"
              aria-expanded={accountOpen}
              onClick={() => {
                setAccountOpen((v) => !v);
                setNotifOpen(false);
              }}
              className="inline-flex size-9 items-center justify-center rounded-full text-content-muted transition hover:bg-surface-overlay/60 hover:text-content focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <User className="size-4" />
            </button>

            {accountOpen && (
              <div
                role="menu"
                className="absolute right-0 mt-2 w-64 overflow-hidden rounded-2xl border border-edge bg-surface-raised/95 shadow-[0_24px_64px_-32px_rgb(0_0_0_/_0.6)] backdrop-blur-xl"
              >
                <div className="border-b border-edge px-4 py-3">
                  <p className="text-sm font-semibold text-content">
                    Analyst
                  </p>
                  <p className="mt-0.5 text-[11px] text-content-subtle">
                    Session not signed in
                  </p>
                </div>
                <div className="px-4 py-6 text-center">
                  <p className="text-xs text-content-muted">
                    Account management is not yet implemented.
                  </p>
                  <p className="mt-1 text-[11px] text-content-subtle">
                    Authentication will be added in a later phase.
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Theme toggle */}
          <div className="pl-1">
            <LiquidThemeToggle />
          </div>
        </div>
      </header>

      {/* Mobile search row — below the pill, only on small screens */}
      {visible && mobileSearchOpen && (
        <div className="mx-auto mt-2 max-w-[1600px] px-1 lg:hidden">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-content-subtle" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search cases…"
              autoFocus
              className="h-10 w-full rounded-full border border-edge bg-surface/85 pl-9 pr-3 text-sm text-content outline-none placeholder:text-content-subtle focus:border-accent backdrop-blur"
            />
          </div>
        </div>
      )}
    </div>
  );
}