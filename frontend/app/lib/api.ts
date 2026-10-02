export const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

export interface Signal {
  id: string;
  title: string;
  severity: string;
  description: string;
  points: number;
}

export interface ScanResult {
  id: number;
  url: string;
  host: string;
  timestamp: string;
  risk_score: number;
  threat_level: string;
  classification: string;
  confidence: number;
  ml_probability: number;
  recommendation: string;
  signals: Signal[];
  features: Record<string, number>;
  breakdown: Record<string, unknown>;
}

export interface HistoryItem {
  id: number;
  url: string;
  host: string;
  timestamp: string;
  risk_score: number;
  threat_level: string;
  classification: string;
  confidence: number;
}

export interface HistoryPage {
  total: number;
  items: HistoryItem[];
}

export interface Stats {
  total_scans: number;
  by_threat_level: Record<string, number>;
  by_classification: Record<string, number>;
  average_risk_score: number;
  top_signals: { signal: string; count: number }[];
  scans_per_day: { date: string; scans: number }[];
}

export const LEVEL_ORDER = ["SAFE", "LOW RISK", "MEDIUM RISK", "HIGH RISK", "CRITICAL"] as const;

const LEVEL_STYLES: Record<string, { hex: string; chip: string }> = {
  SAFE:          { hex: "#10b981", chip: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
  "LOW RISK":    { hex: "#a3e635", chip: "bg-lime-500/10 text-lime-400 border-lime-500/30" },
  "MEDIUM RISK": { hex: "#f59e0b", chip: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
  "HIGH RISK":   { hex: "#f97316", chip: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
  CRITICAL:      { hex: "#ef4444", chip: "bg-red-500/10 text-red-400 border-red-500/30" },
};

export function levelStyle(level: string) {
  return LEVEL_STYLES[level] ?? LEVEL_STYLES["MEDIUM RISK"];
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const message =
      typeof body?.detail === "string" ? body.detail : `Request failed (${res.status})`;
    throw new Error(message);
  }
  return res.json();
}

export async function scanUrl(url: string): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  return handle<ScanResult>(res);
}

export async function getScan(id: string | number): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/api/history/${id}`);
  return handle<ScanResult>(res);
}

export async function getHistory(params: URLSearchParams): Promise<HistoryPage> {
  const res = await fetch(`${API_BASE}/api/history?${params.toString()}`);
  return handle<HistoryPage>(res);
}

export async function getStats(): Promise<Stats> {
  const res = await fetch(`${API_BASE}/api/stats`);
  return handle<Stats>(res);
}