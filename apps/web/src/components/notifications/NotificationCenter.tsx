"use client";

import { useEffect, useId, useState } from "react";
import { useCiccLocale } from "../application/CiccApplication";
import styles from "./NotificationCenter.module.css";

const KEY = "cicc.notification-preferences.v1";
const copy = {
  en: { title: "Notifications", unavailable: "No notification service is connected. The inbox is unavailable and no notifications are fabricated.", localPrefs: "Notification preferences below are stored only in this browser; they are not synchronized to an account or server.", inApp: "In-app notifications (local preference)", email: "Email notifications (local preference)" },
  ar: { title: "الإشعارات", unavailable: "لا توجد خدمة إشعارات متصلة. البريد الوارد غير متاح ولا تُختلق إشعارات.", localPrefs: "تُحفظ تفضيلات الإشعارات أدناه في هذا المتصفح فقط؛ ولا تُزامن إلى حساب أو خادم.", inApp: "إشعارات داخل التطبيق (تفضيل محلي)", email: "إشعارات البريد الإلكتروني (تفضيل محلي)" },
  fa: { title: "اعلان‌ها", unavailable: "سرویس اعلانی متصل نیست. صندوق ورودی در دسترس نیست و اعلانی ساخته نمی‌شود.", localPrefs: "ترجیحات اعلان زیر فقط در این مرورگر ذخیره می‌شوند؛ با حساب یا سرور همگام نیستند.", inApp: "اعلان‌های درون‌برنامه‌ای (ترجیح محلی)", email: "اعلان‌های ایمیلی (ترجیح محلی)" },
} as const;

export function NotificationCenter() {
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
    </section>
  );
}
