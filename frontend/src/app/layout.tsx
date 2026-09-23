import type { Metadata, Viewport } from "next";
import type { JSX, ReactNode } from "react";

import { Toaster } from "@/components/ui/sonner";
import { env } from "@/lib/env";

import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: env.appName,
    template: `%s · ${env.appName}`,
  },
  description:
    "Multi-tenant network audit and port scanning platform for Internet Service Providers.",
  applicationName: env.appName,
  // An internal audit console must never appear in a search index.
  robots: { index: false, follow: false, nocache: true },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0b1120" },
  ],
};

/**
 * Root layout for the dashboard.
 *
 * @param props.children - The active route's rendered tree.
 */
export default function RootLayout({
  children,
}: Readonly<{ children: ReactNode }>): JSX.Element {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background font-sans text-foreground">
        {children}
        <Toaster position="bottom-right" />
      </body>
    </html>
  );
}
