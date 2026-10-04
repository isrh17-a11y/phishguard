"use client";

import { ScanResult, levelStyle } from "../lib/api";

interface FeatureContribution {
  feature: string;
  value: number;
  contribution: number;
}

function Gauge({ score, level }: { score: number; level: string }) {
  const { hex } = levelStyle(level);
  const r = 84;
  const circ = 2 * Math.PI * r;
  const filled = (Math.min(Math.max(score, 0), 100) / 100) * circ;
  return (
    <div className="relative h-52 w-52 shrink-0">
      <svg viewBox="0 0 200 200" className="h-full w-full -rotate-90">
        <circle cx="100" cy="100" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="12" />
        <circle
          cx="100" cy="100" r={r} fill="none" stroke={hex} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${filled} ${circ - filled}`}
          style={{ transition: "stroke-dasharray 900ms ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-5xl font-bold" style={{ color: hex }}>{score}</span>
        <span className="text-xs text-slate-500">/ 100</span>
      </div>
    </div>
  );
}

const SEV_CHIP: Record<string, string> = {
  HIGH: "bg-red-500/10 text-red-400 border-red-500/30",
  MEDIUM: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  LOW: "bg-sky-500/10 text-sky-400 border-sky-500/30",
  INFO: "bg-slate-500/10 text-slate-400 border-slate-500/30",
};

const FEATURE_LABELS: [string, string][] = [
  ["url_length", "URL length"], ["num_subdomains", "Subdomains"], ["path_depth", "Path depth"],
  ["num_dots", "Dots"], ["num_hyphens", "Hyphens"], ["num_digits", "Digits"],
  ["num_special_chars", "Special chars"], ["num_suspicious_keywords", "Suspicious keywords"],
  ["is_https", "HTTPS"], ["has_ip_host", "IP host"], ["suspicious_tld", "Suspicious TLD"],
  ["hostname_entropy", "Hostname entropy"], ["url_entropy", "URL entropy"],
  ["num_hyphens_in_host", "Hyphens in host"], ["digit_ratio", "Digit ratio"],
  ["longest_digit_run", "Longest digit run"], ["has_at_symbol", "@ symbol"],
  ["is_shortener", "Shortener"], ["has_punycode", "Punycode"],
];

function formatValue(v: number): string {
  return Number.isInteger(v) ? String(v) : v.toFixed(2);
}

export default function ResultView({ data }: { data: ScanResult }) {
  const { hex, chip } = levelStyle(data.threat_level);
  const phishPct = Math.round(data.ml_probability * 100);
  const legitPct = 100 - phishPct;
  const topFeatures = data.breakdown?.top_features as FeatureContribution[] | undefined;
  const maxAbs = topFeatures?.length
    ? Math.max(...topFeatures.map(f => Math.abs(f.contribution)))
    : 1;

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      {/* Verdict */}
      <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
        <p className="text-xs font-semibold tracking-widest text-slate-500">SECURITY ASSESSMENT</p>
        <div className="mt-4 flex flex-col items-center gap-8 sm:flex-row">
          <Gauge score={data.risk_score} level={data.threat_level} />
          <div className="min-w-0 flex-1">
            <span className={`inline-block rounded-md border px-3 py-1 text-sm font-semibold ${chip}`}>
              {data.threat_level}
            </span>
            <p className="mt-3 break-all font-mono text-sm text-slate-300">{data.url}</p>
            <div className="mt-4 flex gap-6 text-sm text-slate-400">
              <span>Classification: <b className={data.classification === "PHISHING" ? "text-red-400" : "text-emerald-400"}>{data.classification}</b></span>
              <span>Model confidence: <b className="text-slate-200">{Math.round(data.confidence * 100)}%</b></span>
            </div>
          </div>
        </div>
      </div>

      {/* Signals */}
      <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
        <h2 className="text-sm font-semibold tracking-widest text-slate-500">WHY THIS VERDICT?</h2>
        <div className="mt-4 space-y-3">
          {data.signals.map(s => (
            <div key={s.id} className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${SEV_CHIP[s.severity] ?? SEV_CHIP.INFO}`}>
                    {s.severity}
                  </span>
                  <span className="font-medium text-slate-200">{s.title}</span>
                </div>
                <span className="font-mono text-sm text-slate-500">+{s.points}</span>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">{s.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Model analysis */}
      <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
        <h2 className="text-sm font-semibold tracking-widest text-slate-500">MODEL ANALYSIS — XGBOOST</h2>
        <div className="mt-4 space-y-3 text-sm">
          <div>
            <div className="mb-1 flex justify-between"><span className="text-red-400">Phishing probability</span><span className="font-mono">{phishPct}%</span></div>
            <div className="h-2 overflow-hidden rounded-full bg-white/5"><div className="h-full rounded-full bg-red-500 transition-all duration-700" style={{ width: `${phishPct}%` }} /></div>
          </div>
          <div>
            <div className="mb-1 flex justify-between"><span className="text-emerald-400">Legitimate probability</span><span className="font-mono">{legitPct}%</span></div>
            <div className="h-2 overflow-hidden rounded-full bg-white/5"><div className="h-full rounded-full bg-emerald-500 transition-all duration-700" style={{ width: `${legitPct}%` }} /></div>
          </div>
          {typeof data.breakdown.ml_points === "number" && (
            <p className="pt-2 font-mono text-xs text-slate-500">
              score composition: ML {data.breakdown.ml_points} pts + heuristics {String(data.breakdown.heuristic_points)} pts
            </p>
          )}
        </div>
      </div>

      {/* SHAP per-scan attribution */}
      {topFeatures && topFeatures.length > 0 && (
        <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
          <h2 className="text-sm font-semibold tracking-widest text-slate-500">FEATURE ATTRIBUTION — THIS SCAN (SHAP)</h2>
          <p className="mt-1 text-xs text-slate-500">
            Instance-level explanation: the features that most influenced this specific verdict.
            <span className="text-red-400"> Red pushes toward phishing</span>,
            <span className="text-emerald-400"> green toward legitimate</span>.
          </p>
          <div className="mt-5 space-y-3">
            {topFeatures.map(f => {
              const label = FEATURE_LABELS.find(([k]) => k === f.feature)?.[1]
                ?? f.feature.replaceAll("_", " ");
              const widthPct = (Math.abs(f.contribution) / maxAbs) * 100;
              const towardPhishing = f.contribution >= 0;
              return (
                <div key={f.feature} className="flex items-center gap-3 text-sm">
                  <span className="w-36 shrink-0 truncate text-slate-400" title={f.feature}>{label}</span>
                  <span className="w-10 shrink-0 text-right font-mono text-xs text-slate-500">{formatValue(f.value)}</span>
                  <div className="relative h-5 min-w-0 flex-1 rounded bg-white/5">
                    <div className="absolute inset-y-0 left-1/2 w-px bg-white/20" />
                    <div
                      className={`absolute inset-y-0.5 rounded ${towardPhishing ? "left-1/2 bg-red-500/80" : "right-1/2 bg-emerald-500/80"}`}
                      style={{ width: `${widthPct / 2}%`, transition: "width 700ms ease" }}
                    />
                  </div>
                  <span className={`w-28 shrink-0 font-mono text-xs ${towardPhishing ? "text-red-400" : "text-emerald-400"}`}>
                    {towardPhishing ? "+" : ""}{f.contribution.toFixed(2)} → {towardPhishing ? "phishing" : "legitimate"}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* URL intelligence */}
      <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
        <h2 className="text-sm font-semibold tracking-widest text-slate-500">URL INTELLIGENCE</h2>
        <div className="mt-4 grid grid-cols-2 gap-x-8 gap-y-2 text-sm sm:grid-cols-3">
          {FEATURE_LABELS.map(([key, label]) => {
            const v = data.features[key];
            if (v === undefined) return null;
            const binary = ["is_https", "has_ip_host", "suspicious_tld"].includes(key);
            return (
              <div key={key} className="flex justify-between border-b border-white/5 py-1.5">
                <span className="text-slate-500">{label}</span>
                <b className="font-mono text-slate-200">{binary ? (v === 1 ? "YES" : "NO") : formatValue(v)}</b>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recommendation */}
      <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
        <h2 className="text-sm font-semibold tracking-widest text-slate-500">RECOMMENDATION</h2>
        <p className="mt-3 leading-relaxed text-slate-300">{data.recommendation}</p>
      </div>
    </div>
  );
}