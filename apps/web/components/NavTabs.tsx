"use client";

export interface Tab {
  id: string;
  label: string;
}

export default function NavTabs({
  tabs,
  active,
  onChange,
}: {
  tabs: Tab[];
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <nav aria-label="views" className="mb-6 flex flex-wrap gap-2" role="tablist">
      {tabs.map((tb) => (
        <button
          key={tb.id}
          type="button"
          role="tab"
          aria-selected={active === tb.id}
          onClick={() => onChange(tb.id)}
          className={`rounded-lg border px-3.5 py-1.5 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-cyan-400 ${
            active === tb.id
              ? "border-cyan-500/60 bg-cyan-500/15 text-cyan-200"
              : "border-slate-700 bg-slate-900/60 text-slate-300 hover:border-slate-500"
          }`}
        >
          {tb.label}
        </button>
      ))}
    </nav>
  );
}
