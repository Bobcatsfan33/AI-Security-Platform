import type { Metadata } from "next";
import Link from "next/link";
import { PreviewBadge, isPreviewRoute } from "@/components/PreviewBadge";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI Security Platform",
  description: "Control plane for AI security",
};

interface NavLinkProps {
  href: string;
  label: string;
}

function NavLink({ href, label }: NavLinkProps) {
  return (
    <li>
      <Link
        href={href}
        className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-100"
      >
        {label}
        {isPreviewRoute(href) && <PreviewBadge />}
      </Link>
    </li>
  );
}

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full bg-slate-50 text-slate-900">
        <nav className="border-b border-slate-200 bg-white">
          <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
            <div className="flex items-center gap-6">
              <Link href="/" className="font-semibold text-slate-900">
                AI Security Platform
              </Link>
              <ul className="flex flex-wrap items-center gap-1">
                <NavLink href="/assets" label="Assets" />
                <NavLink href="/narratives" label="Workbench" />
                <NavLink href="/aiguard" label="AI Guard" />
                <NavLink href="/posture" label="Risk Posture" />
                <NavLink href="/redteam" label="Red Team" />
                <NavLink href="/evaluations" label="Evaluations" />
                <NavLink href="/findings" label="Findings" />
                <NavLink href="/test-cases" label="Test Cases" />
                <NavLink href="/reports" label="Reports" />
                {/* Threat Intel is Tier C (frozen): cross-tenant clustering
                    needs cross-tenant data, so with one tenant it is a claim
                    with nothing behind it. The page and its API remain on disk
                    behind PLATFORM_ENABLE_THREAT_INTEL. See docs/TIERS.md. */}
                <NavLink href="/compliance" label="Compliance" />
                <NavLink href="/mcp" label="MCP" />
                <NavLink href="/connectors" label="Connectors" />
              </ul>
            </div>
            <Link
              href="/login"
              className="text-sm text-slate-600 hover:text-slate-900"
            >
              Sign in / Logout
            </Link>
          </div>
        </nav>
        <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
          {children}
        </main>
      </body>
    </html>
  );
}
