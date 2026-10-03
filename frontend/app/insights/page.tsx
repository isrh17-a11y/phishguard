"use client";

import { useEffect, useState } from "react";
import {
  Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Stats, getStats, levelStyle } from "../lib/api";

const TOOLTIP = { backgroundColor: "#101722", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12 };

export default function InsightsPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { getStats().then(setStats).catch(e => setError(e.message)); }, []);

  if (error) return <p className="pt-20 text-center text-red-400">{error}</p>;
  if (!stats) return <p className="pt-20 text-center text-slate-500">Loading insights…</p>;

  const levelData = Object.entries(stats.by_threat_level)
    .map(([level, count]) => ({ level, count, fill: levelStyle(level).hex }))
    .sort((a, b) => a.level.localeCompare(b.level));

  const signalData = stats.top_signals.map(s => ({
    name: s.signal.replaceAll("_", " "), count: s.count,
  }));

  let running = 0;
  const timeline = stats.scans_per_day.map(d => {
    running += d.scans;
    return { date: d.date, scans: running };
  });

  const phishing = stats.by_classification.PHISHING ?? 0;

  return (
    <div className="mx-auto max-w-5xl">
      <h1 className="text-2xl font-bold text-white">Threat Insights</h1>

      <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          ["Total scans", String(stats.total_scans), "text-white"],
          ["Phishing detected", String(phishing), "text-red-400"],
          ["Safe scans", String(stats.by_classification.LEGITIMATE ?? 0), "text-emerald-400"],
          ["Avg risk score", String(stats.average_risk_score), "text-amber-400"],
        ].map(([label, value, color]) => (
          <div key={label} className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
            <p className="text-xs tracking-wider text-slate-500 uppercase">{label}</p>
            <p className={`mt-2 text-3xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6">
          <h2 className="text-sm font-semibold text-slate-400">Risk distribution</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={levelData}>
              <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="level" tick={{ fill: "#64748b", fontSize: 11 }} />
              <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 11 }} width={30} />
              <Tooltip contentStyle={TOOLTIP} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {levelData.map(d => <Cell key={d.level} fill={d.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6">
          <h2 className="text-sm font-semibold text-slate-400">Cumulative scans</h2>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={timeline}>
              <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 11 }} />
              <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 11 }} width={30} />
              <Tooltip contentStyle={TOOLTIP} />
              <Line type="monotone" dataKey="scans" stroke="#10b981" strokeWidth={2} dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6 lg:col-span-2">
          <h2 className="text-sm font-semibold text-slate-400">Most common detection signals</h2>
          <ResponsiveContainer width="100%" height={Math.max(200, signalData.length * 44)}>
            <BarChart data={signalData} layout="vertical">
              <CartesianGrid stroke="rgba(255,255,255,0.05)" horizontal={false} />
              <XAxis type="number" allowDecimals={false} tick={{ fill: "#64748b", fontSize: 11 }} />
              <YAxis type="category" dataKey="name" width={180} tick={{ fill: "#94a3b8", fontSize: 12 }} />
              <Tooltip contentStyle={TOOLTIP} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="count" fill="#10b981" radius={[0, 6, 6, 0]} barSize={16} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}