"use client";

import Section from "./Section";
import StatusBadge from "./StatusBadge";
import { useLocale } from "../lib/i18n";
import type { DependencyGraph as Deps } from "../lib/types";

export default function DependencyGraph({
  deps,
  nameOf,
}: {
  deps: Deps | null;
  nameOf: (key: string) => string;
}) {
  const { t, dir } = useLocale();
  const arrow = dir === "rtl" ? "←" : "→";
  return (
    <Section title={t("depsTitle")}>
      {!deps || deps.nodes.length === 0 ? (
        <p className="text-sm text-slate-400">—</p>
      ) : (
        <>
          <div className="mb-4 flex flex-wrap gap-2">
            {deps.nodes.map((n) => (
              <span
                key={n.key}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-1.5 text-sm text-slate-100"
              >
                {nameOf(n.key)}
                <StatusBadge status={n.status} />
              </span>
            ))}
          </div>
          <ul className="space-y-1.5 text-sm">
            {deps.edges.map((e, i) => (
              <li key={`${e.from}-${e.to}-${i}`} className="text-slate-300">
                <span className="font-medium text-slate-100">
                  {nameOf(e.from)}
                </span>
                <span className="mx-2 text-cyan-400" aria-hidden="true">
                  {arrow}
                </span>
                <span className="font-medium text-slate-100">{nameOf(e.to)}</span>
                <span className="ms-2 text-xs text-slate-500">{e.label}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-slate-500">{t("depsNote")}</p>
        </>
      )}
    </Section>
  );
}
