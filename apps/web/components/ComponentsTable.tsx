"use client";

import Section from "./Section";
import StatusBadge from "./StatusBadge";
import { useLocale } from "../lib/i18n";
import { formatTime } from "../lib/format";
import type { ComponentInfo } from "../lib/types";

export default function ComponentsTable({
  title,
  rows,
  nameOf,
}: {
  title: string;
  rows: ComponentInfo[];
  nameOf: (key: string) => string;
}) {
  const { t, locale } = useLocale();
  return (
    <Section title={title}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <thead>
            <tr className="border-b border-slate-800">
              <th className="th">{t("name")}</th>
              <th className="th">{t("kind")}</th>
              <th className="th">{t("status")}</th>
              <th className="th">{t("detail")}</th>
              <th className="th">{t("lastCheck")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key} className="border-b border-slate-800/60">
                <td className="td font-medium text-slate-100">
                  {nameOf(r.key)}
                </td>
                <td className="td text-slate-400">{t(`kind_${r.kind}`)}</td>
                <td className="td">
                  <StatusBadge status={r.status} />
                </td>
                <td className="td max-w-md text-slate-400">
                  {r.detail || "—"}
                  {r.check && Object.keys(r.check).length > 0 && (
                    <details className="mt-1">
                      <summary className="cursor-pointer text-xs text-cyan-400 hover:text-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyan-400">
                        {t("diagnostics")}
                      </summary>
                      <pre className="mt-1 max-h-48 overflow-auto rounded-md border border-slate-800 bg-slate-950/80 p-2 text-xs text-slate-300">
                        {JSON.stringify(r.check, null, 2)}
                      </pre>
                    </details>
                  )}
                </td>
                <td className="td whitespace-nowrap text-slate-400">
                  {formatTime(r.last_check_at, locale)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
