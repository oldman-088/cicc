"use client";

import { useEffect, useId, useMemo, useState } from "react";
import { useCiccLocale } from "../application/CiccApplication";
import styles from "./InvestigationsWorkspace.module.css";

export type InvestigationStatus = "open" | "in-progress" | "closed";
export type InvestigationNote = { text: string; at: string };
export type Investigation = {
  id: string;
  title: string;
  summary: string;
  status: InvestigationStatus;
  notes: InvestigationNote[];
  entities: string[];
  linkedTaskId: string | null;
  createdAt: string;
};

const STORAGE_KEY = "cicc.investigations.v1";

const messages = {
  en: { eyebrow: "CICC / INVESTIGATIONS", title: "Investigations", localOnly: "Browser-local workspace: investigations are stored only in this browser and are not synchronized, shared, or backed by a server. Entity search covers these local records only; no external entity index is connected.", create: "New investigation", titleLabel: "Title", summaryLabel: "Summary", createButton: "Create investigation", searchLabel: "Search local investigations", statusFilter: "Filter by status", all: "All statuses", empty: "No investigations yet. Create the first local investigation.", noMatches: "No local investigations match this search.", detail: "Investigation detail", notes: "Analyst notes", noteLabel: "Add a note", addNote: "Add note", status: "Status", created: "Created", open: "Open", inProgress: "In progress", closed: "Closed", selectHint: "Select an investigation to view its detail panel." },
  ar: { eyebrow: "CICC / التحقيقات", title: "التحقيقات", localOnly: "مساحة عمل محلية في المتصفح: تُحفظ التحقيقات في هذا المتصفح فقط ولا تُزامَن أو تُشارك أو يدعمها خادم. يغطي البحث هذه السجلات المحلية فقط؛ لا يوجد فهرس كيانات خارجي متصل.", create: "تحقيق جديد", titleLabel: "العنوان", summaryLabel: "الملخص", createButton: "إنشاء تحقيق", searchLabel: "بحث التحقيقات المحلية", statusFilter: "تصفية حسب الحالة", all: "كل الحالات", empty: "لا توجد تحقيقات بعد. أنشئ أول تحقيق محلي.", noMatches: "لا توجد تحقيقات محلية تطابق هذا البحث.", detail: "تفاصيل التحقيق", notes: "ملاحظات المحلل", noteLabel: "إضافة ملاحظة", addNote: "إضافة ملاحظة", status: "الحالة", created: "أُنشئ", open: "مفتوح", inProgress: "قيد التنفيذ", closed: "مغلق", selectHint: "اختر تحقيقاً لعرض لوحة تفاصيله." },
  fa: { eyebrow: "CICC / بررسی‌ها", title: "بررسی‌ها", localOnly: "فضای کاری محلی مرورگر: بررسی‌ها فقط در این مرورگر ذخیره می‌شوند و همگام، اشتراکی یا مبتنی بر سرور نیستند. جست‌وجو فقط همین سوابق محلی را پوشش می‌دهد؛ فهرست موجودیت خارجی متصل نیست.", create: "بررسی جدید", titleLabel: "عنوان", summaryLabel: "خلاصه", createButton: "ایجاد بررسی", searchLabel: "جست‌وجوی بررسی‌های محلی", statusFilter: "پالایش بر اساس وضعیت", all: "همهٔ وضعیت‌ها", empty: "هنوز بررسی‌ای نیست. نخستین بررسی محلی را ایجاد کنید.", noMatches: "بررسی محلی‌ای با این جست‌وجو پیدا نشد.", detail: "جزئیات بررسی", notes: "یادداشت‌های تحلیل‌گر", noteLabel: "افزودن یادداشت", addNote: "افزودن یادداشت", status: "وضعیت", created: "ایجاد شده", open: "باز", inProgress: "در حال انجام", closed: "بسته", selectHint: "برای دیدن جزئیات، یک بررسی را انتخاب کنید." },
} as const;

function load(): Investigation[] {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item) =>
      typeof item === "object" && item !== null &&
      typeof (item as { id?: unknown }).id === "string" &&
      typeof (item as { title?: unknown }).title === "string" &&
      Array.isArray((item as { notes?: unknown }).notes))
      .map((item) => {
        const raw = item as { notes: unknown[]; entities?: unknown; linkedTaskId?: unknown } & Omit<Investigation, "notes" | "entities" | "linkedTaskId">;
        return {
          ...raw,
          // Migrate legacy plain-string notes to timestamped note objects.
          notes: raw.notes.map((n) => typeof n === "string" ? { text: n, at: raw.createdAt } : n as InvestigationNote),
          entities: Array.isArray(raw.entities) ? raw.entities.filter((e): e is string => typeof e === "string") : [],
          linkedTaskId: typeof raw.linkedTaskId === "string" ? raw.linkedTaskId : null,
        };
      });
  } catch { return []; }
}

export function InvestigationsWorkspace() {
  const localeContext = useCiccLocale();
  const locale = localeContext?.locale ?? "en";
  const m = messages[locale];
  const formId = useId().replaceAll(":", "");
  const [items, setItems] = useState<Investigation[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | InvestigationStatus>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [note, setNote] = useState("");

  useEffect(() => { setItems(load()); setLoaded(true); }, []);
  useEffect(() => { if (loaded) window.localStorage.setItem(STORAGE_KEY, JSON.stringify(items)); }, [items, loaded]);

  const filtered = useMemo(() => {
    const q = query.trim().toLocaleLowerCase(locale);
    return items.filter((item) =>
      (statusFilter === "all" || item.status === statusFilter) &&
      (!q || [item.title, item.summary, item.linkedTaskId ?? "", ...item.entities, ...item.notes.map((n) => n.text)].join(" ").toLocaleLowerCase(locale).includes(q)));
  }, [items, query, statusFilter, locale]);

  const selected = items.find((item) => item.id === selectedId) ?? filtered[0] ?? null;
  const statusLabel = (s: InvestigationStatus) => s === "open" ? m.open : s === "in-progress" ? m.inProgress : m.closed;

  return (
    <div className={styles.page} lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <header>
        <p className={styles.eyebrow}>{m.eyebrow}</p>
        <h1>{m.title}</h1>
        <p role="note">{m.localOnly}</p>
      </header>

      <section aria-labelledby={`${formId}-create`} className={styles.panel}>
        <h2 id={`${formId}-create`}>{m.create}</h2>
        <form onSubmit={(event) => {
          event.preventDefault();
          if (!title.trim()) return;
          const item: Investigation = { id: `inv-${Date.now()}`, title: title.trim(), summary: summary.trim(), status: "open", notes: [], entities: [], linkedTaskId: null, createdAt: new Date().toISOString() };
          setItems((current) => [item, ...current]); setSelectedId(item.id); setTitle(""); setSummary("");
        }}>
          <label>{m.titleLabel}<input value={title} onChange={(e) => setTitle(e.target.value)} required /></label>
          <label>{m.summaryLabel}<textarea value={summary} onChange={(e) => setSummary(e.target.value)} /></label>
          <button type="submit">{m.createButton}</button>
        </form>
      </section>

      <div className={styles.controls} role="search">
        <label>{m.searchLabel}<input type="search" value={query} onChange={(e) => setQuery(e.target.value)} /></label>
        <label>{m.statusFilter}
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as typeof statusFilter)}>
            <option value="all">{m.all}</option><option value="open">{m.open}</option>
            <option value="in-progress">{m.inProgress}</option><option value="closed">{m.closed}</option>
          </select>
        </label>
      </div>

      <div className={styles.layout}>
        <section aria-label={m.title} className={styles.panel}>
          {items.length === 0 ? <p>{m.empty}</p> : filtered.length === 0 ? <p>{m.noMatches}</p> : (
            <ul className={styles.list}>{filtered.map((item) => (
              <li key={item.id}>
                <button type="button" onClick={() => setSelectedId(item.id)} aria-current={selected?.id === item.id}>
                  <bdi dir="auto">{item.title}</bdi> · {statusLabel(item.status)}
                </button>
              </li>))}
            </ul>)}
        </section>

        <section aria-labelledby={`${formId}-detail`} className={styles.panel}>
          <h2 id={`${formId}-detail`}>{m.detail}</h2>
          {!selected ? <p>{m.selectHint}</p> : (
            <>
              <h3><bdi dir="auto">{selected.title}</bdi></h3>
              {selected.summary && <p dir="auto">{selected.summary}</p>}
              <p>{m.created}: {selected.createdAt}</p>
              <label>{m.status}
                <select value={selected.status} onChange={(e) => setItems((cur) => cur.map((i) => i.id === selected.id ? { ...i, status: e.target.value as InvestigationStatus } : i))}>
                  <option value="open">{m.open}</option><option value="in-progress">{m.inProgress}</option><option value="closed">{m.closed}</option>
                </select>
              </label>
              <div>
                <h4>{locale === "ar" ? "الكيانات المرتبطة" : locale === "fa" ? "موجودیت‌های مرتبط" : "Associated entities"}</h4>
                <ul>{selected.entities.map((e) => <li key={e}><bdi dir="auto">{e}</bdi></li>)}</ul>
                <form onSubmit={(ev) => { ev.preventDefault(); const input = new FormData(ev.currentTarget).get("entity"); if (typeof input !== "string" || !input.trim()) return; setItems((cur) => cur.map((i) => i.id === selected.id ? { ...i, entities: [...i.entities, input.trim()] } : i)); ev.currentTarget.reset(); }}>
                  <label>{locale === "ar" ? "إضافة كيان" : locale === "fa" ? "افزودن موجودیت" : "Add entity (name or ID)"}<input name="entity" /></label>
                  <button type="submit">{locale === "ar" ? "إضافة" : locale === "fa" ? "افزودن" : "Add entity"}</button>
                </form>
                <label>{locale === "ar" ? "معرّف مهمة التنسيق المرتبطة" : locale === "fa" ? "شناسهٔ وظیفهٔ هماهنگی مرتبط" : "Linked coordination task ID"}
                  <input value={selected.linkedTaskId ?? ""} placeholder="api-…" onChange={(ev) => { const v = ev.target.value; setItems((cur) => cur.map((i) => i.id === selected.id ? { ...i, linkedTaskId: v || null } : i)); }} />
                </label>
                {selected.linkedTaskId && <p><a href={`/coordination?task=${encodeURIComponent(selected.linkedTaskId)}`}>{locale === "ar" ? "فتح في التنسيق" : locale === "fa" ? "بازکردن در هماهنگی" : "Open in Coordination"}</a></p>}
                <h4>{locale === "ar" ? "الخط الزمني" : locale === "fa" ? "گاه‌شمار" : "Timeline"}</h4>
                <ol>
                  <li>{m.created}: {selected.createdAt}</li>
                  {[...selected.notes].sort((a, b) => a.at.localeCompare(b.at)).map((n, i) => <li key={i}>{n.at} — <bdi dir="auto">{n.text}</bdi></li>)}
                </ol>
              </div>
              <h4>{m.notes}</h4>
              <ul>{selected.notes.map((n, i) => <li key={i} dir="auto">{n.text} <small>({n.at})</small></li>)}</ul>
              <form onSubmit={(e) => { e.preventDefault(); if (!note.trim()) return;
                setItems((cur) => cur.map((i) => i.id === selected.id ? { ...i, notes: [...i.notes, { text: note.trim(), at: new Date().toISOString() }] } : i)); setNote(""); }}>
                <label>{m.noteLabel}<input value={note} onChange={(e) => setNote(e.target.value)} /></label>
                <button type="submit">{m.addNote}</button>
              </form>
            </>)}
        </section>
      </div>
    </div>
  );
}
