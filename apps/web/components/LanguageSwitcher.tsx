"use client";

import { useLocale } from "../lib/i18n";
import { LOCALES } from "../lib/locales.mjs";

const LABELS: Record<string, string> = { en: "English", ar: "العربية" };

export default function LanguageSwitcher() {
  const { locale, setLocale, t } = useLocale();
  return (
    <div
      className="flex items-center gap-2"
      role="group"
      aria-label={t("language")}
    >
      <span className="text-xs text-slate-400">{t("language")}:</span>
      {(LOCALES as string[]).map((l) => (
        <button
          key={l}
          type="button"
          onClick={() => setLocale(l as "en" | "ar")}
          aria-pressed={locale === l}
          className={`rounded-md border px-2.5 py-1 text-xs font-medium transition focus:outline-none focus:ring-2 focus:ring-cyan-400 ${
            locale === l
              ? "border-cyan-500/60 bg-cyan-500/15 text-cyan-200"
              : "border-slate-700 bg-slate-800/60 text-slate-300 hover:border-slate-500"
          }`}
        >
          {LABELS[l]}
        </button>
      ))}
    </div>
  );
}
