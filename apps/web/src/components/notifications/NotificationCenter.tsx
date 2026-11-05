"use client";

import { useEffect, useId, useState } from "react";
import { useCiccLocale } from "../application/CiccApplication";
import styles from "./NotificationCenter.module.css";

const KEY = "cicc.notification-preferences.v1";
const REMINDERS_KEY = "cicc.local-reminders.v1";
type Reminder = { id: string; text: string; category: "investigation" | "operations" | "intelligence"; read: boolean; at: string };
const copy = {
  en: { title: "Notifications", unavailable: "No notification service is connected. The inbox is unavailable and no notifications are fabricated.", localPrefs: "Notification preferences below are stored only in this browser; they are not synchronized to an account or server.", inApp: "In-app notifications (local preference)", email: "Email notifications (local preference)" },
  ar: { title: "الإشعارات", unavailable: "لا توجد خدمة إشعارات متصلة. البريد الوارد غير متاح ولا تُختلق إشعارات.", localPrefs: "تُحفظ تفضيلات الإشعارات أدناه في هذا المتصفح فقط؛ ولا تُزامن إلى حساب أو خادم.", inApp: "إشعارات داخل التطبيق (تفضيل محلي)", email: "إشعارات البريد الإلكتروني (تفضيل محلي)" },
  fa: { title: "اعلان‌ها", unavailable: "سرویس اعلانی متصل نیست. صندوق ورودی در دسترس نیست و اعلانی ساخته نمی‌شود.", localPrefs: "ترجیحات اعلان زیر فقط در این مرورگر ذخیره می‌شوند؛ با حساب یا سرور همگام نیستند.", inApp: "اعلان‌های درون‌برنامه‌ای (ترجیح محلی)", email: "اعلان‌های ایمیلی (ترجیح محلی)" },
} as const;

export function NotificationCenter() {
  const [reminders, setReminders] = useState<Reminder[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<"all" | Reminder["category"]>("all");
  const unreadCount = reminders.filter((r) => !r.read).length;
  const visibleReminders = categoryFilter === "all" ? reminders : reminders.filter((r) => r.category === categoryFilter);
  useEffect(() => { try { const raw = window.localStorage.getItem(REMINDERS_KEY); if (raw) { const parsed: unknown = JSON.parse(raw); if (Array.isArray(parsed)) setReminders(parsed.filter((r): r is Reminder => typeof r === "object" && r !== null && typeof (r as Reminder).text === "string")); } } catch { /* keep empty */ } }, []);
  const saveReminders = (next: Reminder[]) => { setReminders(next); try { window.localStorage.setItem(REMINDERS_KEY, JSON.stringify(next)); } catch { /* ignore */ } };
  const localeContext = useCiccLocale();
  const locale = localeContext?.locale ?? "en";
  const m = copy[locale];
  const id = useId().replaceAll(":", "");
  const [prefs, setPrefs] = useState({ inApp: true, email: false });
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(KEY);
      if (raw) { const p: unknown = JSON.parse(raw); if (typeof p === "object" && p !== null) setPrefs({ inApp: Boolean((p as {inApp?: unknown}).inApp), email: Boolean((p as {email?: unknown}).email) }); }
    } catch { /* keep defaults */ }
  }, []);
  const update = (next: typeof prefs) => { setPrefs(next); try { window.localStorage.setItem(KEY, JSON.stringify(next)); } catch { /* storage unavailable */ } };
  return (
    <section className={styles.panel} aria-labelledby={`${id}-title`} lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <h2 id={`${id}-title`}>{m.title}</h2>
      <p role="note">{m.unavailable}</p>
      <p>{m.localPrefs}</p>
      <label><input type="checkbox" checked={prefs.inApp} onChange={(e) => update({ ...prefs, inApp: e.target.checked })} /> {m.inApp}</label>
      <label><input type="checkbox" checked={prefs.email} onChange={(e) => update({ ...prefs, email: e.target.checked })} /> {m.email}</label>
      <div>
        <h3>{locale === "ar" ? "تذكيرات محلية (أنشأها المستخدم، هذا المتصفح فقط)" : locale === "fa" ? "یادآورهای محلی (ساختهٔ کاربر، فقط این مرورگر)" : "Local reminders (user-created, this browser only)"}</h3>
        <form onSubmit={(e) => { e.preventDefault(); const data = new FormData(e.currentTarget); const text = data.get("text"); const category = data.get("category"); if (typeof text !== "string" || !text.trim()) return; saveReminders([{ id: `rem-${Date.now()}`, text: text.trim(), category: category === "operations" || category === "intelligence" ? category : "investigation", read: false, at: new Date().toISOString() }, ...reminders]); e.currentTarget.reset(); }}>
          <label>{locale === "ar" ? "نص التذكير" : locale === "fa" ? "متن یادآور" : "Reminder text"}<input name="text" required /></label>
          <label>{locale === "ar" ? "الفئة" : locale === "fa" ? "دسته" : "Category"}
            <select name="category"><option value="investigation">investigation</option><option value="operations">operations</option><option value="intelligence">intelligence</option></select>
          </label>
          <button type="submit">{locale === "ar" ? "إضافة تذكير محلي" : locale === "fa" ? "افزودن یادآور محلی" : "Add local reminder"}</button>
        </form>
        <p role="status">{locale === "ar" ? `غير مقروء: ${unreadCount}` : locale === "fa" ? `خوانده‌نشده: ${unreadCount}` : `Unread: ${unreadCount}`}</p>
        <label>{locale === "ar" ? "تصفية حسب الفئة" : locale === "fa" ? "فیلتر بر اساس دسته" : "Filter by category"}
          <select value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value as typeof categoryFilter)}>
            <option value="all">{locale === "ar" ? "كل الفئات" : locale === "fa" ? "همهٔ دسته‌ها" : "All categories"}</option>
            <option value="investigation">investigation</option><option value="operations">operations</option><option value="intelligence">intelligence</option>
          </select>
        </label>{" "}
        <button type="button" disabled={unreadCount === 0} onClick={() => saveReminders(reminders.map((r) => ({ ...r, read: true })))}>{locale === "ar" ? "وضع علامة مقروء على الكل" : locale === "fa" ? "علامت خوانده‌شده برای همه" : "Mark all read"}</button>
        <ul>
          {visibleReminders.map((r) => (
            <li key={r.id}>
              <bdi dir="auto">{r.text}</bdi> · <span>{r.category}</span> · <span>{r.read ? (locale === "ar" ? "مقروء" : locale === "fa" ? "خوانده‌شده" : "read") : (locale === "ar" ? "غير مقروء" : locale === "fa" ? "خوانده‌نشده" : "unread")}</span>{" "}
              <button type="button" onClick={() => saveReminders(reminders.map((x) => x.id === r.id ? { ...x, read: !x.read } : x))}>{r.read ? (locale === "ar" ? "وضع علامة غير مقروء" : locale === "fa" ? "علامت خوانده‌نشده" : "Mark unread") : (locale === "ar" ? "وضع علامة مقروء" : locale === "fa" ? "علامت خوانده‌شده" : "Mark read")}</button>
            </li>))}
        </ul>
      </div>
    </section>
  );
}
