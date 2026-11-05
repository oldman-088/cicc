"use client";

import { useMemo, useState } from "react";

export type IntelligenceRecordSummary = {
  id: string;
  name: string;
  kind: string;
  confidence: number;
  verification: string;
  provenanceSources: string[];
};

export function filterIntelligenceRecords(records: readonly IntelligenceRecordSummary[], query: string, kind: string): IntelligenceRecordSummary[] {
  const q = query.trim().toLowerCase();
  return records.filter((r) => (kind === "all" || r.kind === kind) && (!q || [r.id, r.name, r.kind, ...r.provenanceSources].join(" ").toLowerCase().includes(q)));
}

export function IntelligenceList({ records, emptyMessage }: { records: readonly IntelligenceRecordSummary[]; emptyMessage: string }) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const kinds = useMemo(() => ["all", ...new Set(records.map((r) => r.kind))], [records]);
  const filtered = filterIntelligenceRecords(records, query, kind);
  const selected = records.find((r) => r.id === selectedId) ?? null;
  return (
    <div>
      <div role="search">
        <label>Search records<input type="search" value={query} onChange={(e) => setQuery(e.target.value)} /></label>
        <label>Kind
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            {kinds.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
        </label>
      </div>
      {filtered.length === 0 ? <p>{emptyMessage}</p> : (
        <ul>{filtered.map((r) => (
          <li key={r.id}><button type="button" onClick={() => setSelectedId(r.id)} aria-current={selected?.id === r.id}>
            <bdi dir="auto">{r.name}</bdi> · {r.kind} · confidence {r.confidence} · {r.verification}
          </button></li>))}
        </ul>)}
      {selected && (
        <aside aria-label={`Detail for ${selected.name}`}>
          <h3><bdi dir="auto">{selected.name}</bdi></h3>
          <p>ID: <bdi dir="ltr">{selected.id}</bdi></p>
          <p>Confidence: {selected.confidence} (distinct from verification: {selected.verification})</p>
          <p>Provenance sources: {selected.provenanceSources.join(", ") || "none recorded"}</p>
        </aside>)}
    </div>
  );
}
