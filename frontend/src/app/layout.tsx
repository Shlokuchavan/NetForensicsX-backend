import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { ThemeProvider } from "@/components/theme-provider";
import { AmbientBackdrop } from "@/components/nfx/ambient-backdrop";
import { TopNav } from "@/components/TopNav";
import { SearchProvider } from "@/components/SearchContext";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "NetForensicX",
    template: "%s · NetForensicX",
  },
  description:
    "Network forensics and incident investigation platform. Analyze PCAP evidence, reconstruct timelines, and correlate indicators of compromise.",
  applicationName: "NetForensicX",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#080b11" },
  ],
  width: "device-width",
  initialScale: 1,
};

const themeBootstrap = `
(function () {
  try {
    var stored = localStorage.getItem("netforensicx-theme");
    var theme = stored === "light" || stored === "dark" ? stored : "dark";
    var root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
    root.style.colorScheme = theme;
  } catch (e) {
    document.documentElement.classList.add("dark");
  }
})();
`;

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} nfx-scroll-smooth`}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body className="relative min-h-screen bg-surface font-sans text-content antialiased">
        <AmbientBackdrop />
        <ThemeProvider>
          <SearchProvider>
            <TopNav />
            <main className="nfx-page-enter">{children}</main>
          </SearchProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}