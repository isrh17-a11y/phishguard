import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishGuard — Know Before You Click",
  description: "AI-powered URL security intelligence",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">
        <header className="sticky top-0 z-50 border-b border-white/5 bg-[#0a0f16]/80 backdrop-blur">
          <nav className="mx-auto mt-3 flex h-12 max-w-fit items-center justify-center gap-8 rounded-full border border-white/10 bg-white/[0.04] px-8 text-sm text-slate-400 backdrop-blur">
            <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight text-white">
              <span className="text-emerald-400">◈</span> PhishGuard
            </Link>
            <div className="flex items-center gap-6 text-sm text-slate-400">
              <Link href="/" className="transition hover:text-white">Scanner</Link>
              <Link href="/history" className="transition hover:text-white">History</Link>
              <Link href="/insights" className="transition hover:text-white">Insights</Link>
            </div>
          </nav>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-10">{children}</main>
        <footer className="border-t border-white/5 py-6 text-center text-xs text-slate-500">
          PhishGuard · XGBoost classifier + heuristic risk engine · B.Tech Data Science project
        </footer>
      </body>
    </html>
  );
}