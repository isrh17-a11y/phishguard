"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { scanUrl } from "./lib/api";

const STAGES = [
  "Validating URL",
  "Parsing URL structure",
  "Extracting lexical features",
  "Running ML detection (XGBoost)",
  "Applying heuristic signals",
  "Compiling risk assessment",
];

const CHIPS = [
  { icon: "⚡", text: "28 lexical features", className: "left-[2%] top-[280px]" },
  { icon: "🧠", text: "XGBoost classifier", className: "right-[2%] top-[280px]" },
  { icon: "🛡", text: "Heuristic risk engine", className: "right-[2%] top-[430px]" },
];

export default function Home() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [stage, setStage] = useState(0);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) { setError("Paste a URL to analyze."); return; }
    setError(null);
    setScanning(true);
    setStage(0);

    const ticker = setInterval(() => setStage(s => Math.min(s + 1, STAGES.length - 1)), 420);
    const started = Date.now();
    try {
      const result = await scanUrl(trimmed);
      const elapsed = Date.now() - started;
      if (elapsed < 2400) await new Promise(r => setTimeout(r, 2400 - elapsed));
      router.push(`/scan/${result.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
      setScanning(false);
    } finally {
      clearInterval(ticker);
    }
  }

  return (
    <div className="relative">
      {/* backdrop: grid + glow + radar */}
      <div className="pointer-events-none absolute inset-0 -z-10">
        <div className="bg-grid absolute inset-0 [mask-image:radial-gradient(ellipse_65%_55%_at_50%_0%,black,transparent)]" />
        <div
          className="absolute inset-x-0 top-0 h-[520px]"
          style={{ background: "radial-gradient(700px 320px at 50% 0%, rgba(16,185,129,0.16), transparent 70%)" }}
        />
        <div className="absolute inset-x-0 top-40 mx-auto h-[560px] w-[560px] max-w-[100vw] opacity-70">
          <div className="absolute inset-0 rounded-full border border-emerald-500/10" />
          <div className="absolute inset-16 rounded-full border border-emerald-500/15" />
          <div className="absolute inset-32 rounded-full border border-emerald-500/20" />
          <div className="absolute inset-48 rounded-full border border-emerald-500/25" />
          <div
            className="radar-sweep absolute inset-0 rounded-full"
            style={{ background: "conic-gradient(from 0deg, rgba(16,185,129,0.18), transparent 70deg)" }}
          />
        </div>
      </div>

      {/* floating glass chips */}
      {CHIPS.map(c => (
        <div
          key={c.text}
          className={`absolute hidden items-center gap-2 rounded-full border border-white/10 bg-white/[0.05] px-4 py-2 text-xs text-slate-300 backdrop-blur xl:flex ${c.className}`}
        >
          <span>{c.icon}</span> {c.text}
        </div>
      ))}

      <div className="relative flex flex-col items-center px-4">
        <p className="mb-4 rounded-full border border-emerald-500/20 bg-emerald-500/5 px-4 py-1 text-xs font-medium text-emerald-400 backdrop-blur">
          AI-powered URL security intelligence
        </p>
        <h1 className="text-hero-gradient text-center text-6xl font-bold leading-[1.05] tracking-tight sm:text-7xl lg:text-8xl">
          Know Before<br />You Click.
        </h1>
        <p className="mt-5 max-w-xl text-center text-slate-400">
          PhishGuard analyzes any link with a trained ML classifier and a rule-based
          risk engine — and shows you exactly why a URL is safe or dangerous.
        </p>

        <form onSubmit={handleScan} className="mt-12 w-full max-w-2xl">
          <div className="flex overflow-hidden rounded-full border border-white/10 bg-white/[0.04] shadow-[0_0_60px_-15px_rgba(16,185,129,0.35)] backdrop-blur transition focus-within:border-emerald-500/50">
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              disabled={scanning}
              placeholder="https://example.com/login..."
              spellCheck={false}
              className="w-full bg-transparent px-6 py-4 font-mono text-sm text-white outline-none placeholder:text-slate-600"
            />
            <button
              type="submit"
              disabled={scanning}
              className="shrink-0 rounded-full bg-emerald-500 px-8 text-sm font-semibold text-black transition hover:bg-emerald-400 disabled:opacity-40"
            >
              {scanning ? "..." : "SCAN"}
            </button>
          </div>
          {error && <p className="mt-3 text-center text-sm text-red-400">{error}</p>}
        </form>

        {scanning && (
          <div className="relative mt-12 w-full max-w-md overflow-hidden rounded-xl border border-emerald-500/20 bg-white/[0.02] p-6 font-mono text-sm backdrop-blur">
            <div className="scan-line absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-emerald-400/80 to-transparent" />
            {STAGES.map((s, i) => (
              <div key={s} className="flex items-center gap-3 py-1.5">
                <span className={i < stage ? "text-emerald-400" : i === stage ? "text-amber-400" : "text-slate-600"}>
                  {i < stage ? "✓" : i === stage ? "◉" : "○"}
                </span>
                <span className={i <= stage ? "text-slate-200" : "text-slate-600"}>{s}</span>
              </div>
            ))}
          </div>
        )}

        <div className="mt-20 grid w-full max-w-3xl grid-cols-1 gap-4 sm:grid-cols-3">
          {[
            ["Paste URL", "Drop in any link — suspicious or familiar."],
            ["Analyze", "28 lexical features + XGBoost + heuristic rules."],
            ["Understand", "A transparent risk score with every signal explained."],
          ].map(([t, d]) => (
            <div key={t} className="rounded-xl border border-white/10 bg-white/[0.03] p-5 backdrop-blur">
              <h3 className="font-semibold text-white">{t}</h3>
              <p className="mt-1 text-sm text-slate-400">{d}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}