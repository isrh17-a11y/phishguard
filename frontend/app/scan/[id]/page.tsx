"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ScanResult, getScan } from "../../lib/api";
import ResultView from "../../components/ResultView";

export default function ScanReportPage() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getScan(id).then(setData).catch(e => setError(e instanceof Error ? e.message : "Failed to load"));
  }, [id]);

  if (error) return <p className="pt-20 text-center text-red-400">{error}</p>;
  if (!data) return <p className="pt-20 text-center text-slate-500">Loading report…</p>;
  return <ResultView data={data} />;
}