"use client";

import Link from "next/link";
import { useEffect, useId, useMemo, useState } from "react";
import { useCiccLocale } from "../application/CiccApplication";
import styles from "./LocalDataSearch.module.css";

type LocalResult = { kind: "investigation" | "reminder"; title: string; detail: string; href: string };

const INVESTIGATIONS_KEY = "cicc.investigations.v1";
const REMINDERS_KEY = "cicc.local-reminders.v1";

const copy = {
  en: {
    title: "Search local data",
    label: "Search investigations and reminders stored in this browser",
    boundary: "This searches only data stored in this browser (investigations and local reminders). Server-side global search across providers is not available yet; no query leaves this device.",
    none: "No local records match this search.",
    investigation: "Investigation (local)",
    reminder: "Reminder (local)",
  },
  ar: {
    title: "البحث في البيانات المحلية",
    label: "البحث في التحقيقات والتذكيرات المحفوظة في هذا المتصفح",
    boundary: "يبحث هذا في البيانات المحفوظة في هذا المتصفح فقط (التحقيقات والتذكيرات المحلية). البحث الشامل من الخادم عبر المزوّدين غير متاح بعد؛ ولا يغادر أي استعلام هذا الجهاز.",
    none: "لا تطابق أي سجلات محلية هذا البحث.",
    investigation: "تحقيق (محلي)",
    reminder: "تذكير (محلي)",
  },
  fa: {
    title: "جست‌وجو در داده‌های محلی",
    label: "جست‌وجو در تحقیقات و یادآورهای ذخیره‌شده در این مرورگر",
    boundary: "این فقط در داده‌های ذخیره‌شده در این مرورگر جست‌وجو می‌کند (تحقیقات و یادآورهای محلی). جست‌وجوی سراسری سمت سرور میان منابع هنوز در دسترس نیست؛ هیچ درخواستی از این دستگاه خارج نمی‌شود.",
    none: "هیچ رکورد محلی با این جست‌وجو هم‌خوان نیست.",
    investigation: "تحقیق (محلی)",
    reminder: "یادآور (محلی)",
  },
} as const;

function loadLocalResults(): LocalResult[] {
  const results: LocalResult[] = [];
  try {
    const raw = window.localStorage.getItem(INVESTIGATIONS_KEY);
    if (raw) {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const item of parsed) {
          if (typeof item !== "object" || item === null) continue;
          const inv = item as { title?: unknown; summary?: unknown; entities?: unknown; notes?: unknown };
          if (typeof inv.title !== "string") continue;
          const notes = Array.isArray(inv.notes) ? inv.notes.map((n) => (typeof n === "string" ? n : (n as { text?: unknown })?.text)).filter((t): t is string => typeof t === "string") : [];
          const entities = Array.isArray(inv.entities) ? inv.entities.filter((e): e is string => typeof e === "string") : [];
          const detail = [typeof inv.summary === "string" ? inv.summary : "", ...entities, ...notes].join(" · ");
          results.push({ kind: "investigation", title: inv.title, detail, href: "/investigations" });
        }
      }
    }
  } catch { /* malformed local data is ignored, never fabricated */ }
  try {
    const raw = window.localStorage.getItem(REMINDERS_KEY);
    if (raw) {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const item of parsed) {
          if (typeof item !== "object" || item === null) continue;
          const rem = item as { text?: unknown; category?: unknown };
          if (typeof rem.text !== "string") continue;
          results.push({ kind: "reminder", title: rem.text, detail: typeof rem.category === "string" ? rem.category : "", href: "/settings" });
        }
      }
    }
  } catch { /* ignore */ }
  return results;
}

export function LocalDataSearch() {
  const locale = useCiccLocale()?.locale ?? "en";
  const m = copy[locale];
  const id = useId().replaceAll(":", "");
  const [query, setQuery] = useState("");
  const [all, setAll] = useState<LocalResult[]>([]);
  useEffect(() => { setAll(loadLocalResults()); }, []);

  const results = useMemo(() => {
    const q = query.trim().toLocaleLowerCase(locale);
    if (!q) return [];
    return all.filter((r) => `${r.title} ${r.detail}`.toLocaleLowerCase(locale).includes(q));
  }, [all, query, locale]);

  return (
    <section className={styles.panel} aria-labelledby={`${id}-title`} lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <h2 id={`${id}-title`}>{m.title}</h2>
      <p role="note">{m.boundary}</p>
      <label htmlFor={`${id}-query`}>{m.label}</label>
      <input id={`${id}-query`} type="search" value={query} onChange={(e) => setQuery(e.target.value)} />
      <div aria-live="polite">
        {query.trim() && (results.length > 0 ? (
          <ul>
            {results.map((r, index) => (
              <li key={`${r.kind}-${r.title}-${index}`}>
                <Link href={r.href}><bdi dir="auto">{r.title}</bdi></Link>{" "}
                <span>{r.kind === "investigation" ? m.investigation : m.reminder}</span>
                {r.detail && <> · <bdi dir="auto">{r.detail}</bdi></>}
              </li>
            ))}
          </ul>
        ) : <p>{m.none}</p>)}
      </div>
    </section>
  );
}
