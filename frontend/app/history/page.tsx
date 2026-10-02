"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { HistoryItem, getHistory, levelStyle } from "../lib/api";

export default function HistoryPage() {
  const [search, setSearch] = useState("");
  const [data, setData] = useState<{ total: number; items: HistoryItem[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (s: string) => {
    try {
      const params = new URLSearchParams();
      if (s) params.set("search", s);
      setData(await getHistory(params));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the API");
    }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => load(search), 300);
    return () => clearTimeout(t);
  }, [search, load]);

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="text-2xl font-bold text-white">Scan History</h1>
      <p className="mt-1 text-sm text-slate-500">{data ? `${data.total} scans` : " "}</p>

      <input
        value={search}
        onChange={e => setSearch(e.target.value)}
        placeholder="Search URLs…"
        spellCheck={false}
        className="mt-6 w-full rounded-xl border border-white/10 bg-white/[0.03] px-5 py-3 font-mono text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-emerald-500/40"
      />

      {error && (
        <p className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error} — is the backend running?
        </p>
      )}

      <div className="mt-6 overflow-hidden rounded-xl border border-white/10">
        {data?.items.map(item => {
          const { chip } = levelStyle(item.threat_level);
          return (
            <Link
              key={item.id}
              href={`/scan/${item.id}`}
              className="flex items-center gap-4 border-b border-white/5 px-5 py-4 transition last:border-0 hover:bg-white/[0.03]"
            >
              <div className="min-w-0 flex-1">
                <p className="truncate font-mono text-sm text-slate-200">{item.url}</p>
                <p className="text-xs text-slate-500">{new Date(item.timestamp).toLocaleString()}</p>
              </div>
              <span className="font-mono text-lg font-bold text-slate-300">{item.risk_score}</span>
              <span className={`w-28 rounded-md border px-2 py-1 text-center text-xs font-semibold ${chip}`}>
                {item.threat_level}
              </span>
            </Link>
          );
        })}
        {data && data.items.length === 0 && (
          <p className="px-5 py-10 text-center text-sm text-slate-500">No scans match your search.</p>
        )}
      </div>
    </div>
  );
}