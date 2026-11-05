"use client";

import { useId } from "react";
import { isLocale, type Locale } from "./localization";
import { useCiccPreferences } from "./CiccApplication";
import styles from "./SettingsPage.module.css";

type SettingsMessages = {
  eyebrow: string;
  title: string;
  introduction: string;
  preferencesGroupTitle: string;
  languageTitle: string;
  languageDescription: string;
  languageLabel: string;
  motionTitle: string;
  motionDescription: string;
  motionLabel: string;
  integrationTitle: string;
  integrationDescription: string;
};

const settingsMessages: Record<Locale, SettingsMessages> = {
  en: {
    eyebrow: "CICC / PREFERENCES",
    title: "Settings",
    introduction: "Manage interface language and accessibility preferences.",
    preferencesGroupTitle: "Preferences",
    languageTitle: "Interface language",
    languageDescription: "This language is shared across navigation and supported modules, then saved only in this browser. It is not synced to an account.",
    languageLabel: "Choose interface language",
    motionTitle: "Motion",
    motionDescription: "The operating system's reduced-motion preference is always respected. This additional preference is stored only in this browser.",
    motionLabel: "Reduce motion in CICC",
    integrationTitle: "Account and tenant settings",
    integrationDescription: "These controls are not available: this frontend has no verified identity, tenant, or preference-service contract.",
  },
  ar: {
    eyebrow: "CICC / التفضيلات",
    title: "الإعدادات",
    introduction: "إدارة لغة الواجهة وتفضيلات إمكانية الوصول.",
    preferencesGroupTitle: "التفضيلات",
    languageTitle: "لغة الواجهة",
    languageDescription: "تُستخدم اللغة في التنقل والوحدات المدعومة، ثم تُحفظ في هذا المتصفح فقط ولا تُزامن مع حساب.",
    languageLabel: "اختيار لغة الواجهة",
    motionTitle: "الحركة",
    motionDescription: "يُحترم دائماً تفضيل تقليل الحركة في نظام التشغيل. ويُحفظ هذا التفضيل الإضافي في هذا المتصفح فقط.",
    motionLabel: "تقليل الحركة في CICC",
    integrationTitle: "إعدادات الحساب والمستأجر",
    integrationDescription: "هذه الخيارات غير متاحة: لا يوجد في هذه الواجهة عقد موثّق للهوية أو المستأجر أو خدمة التفضيلات.",
  },
  fa: {
    eyebrow: "CICC / ترجیحات",
    title: "تنظیمات",
    introduction: "مدیریت زبان رابط و ترجیحات دسترس‌پذیری.",
    preferencesGroupTitle: "ترجیحات",
    languageTitle: "زبان رابط کاربری",
    languageDescription: "این زبان در پیمایش و ماژول‌های پشتیبانی‌شده مشترک است و فقط در همین مرورگر ذخیره می‌شود؛ با حساب همگام‌سازی نمی‌شود.",
    languageLabel: "انتخاب زبان رابط کاربری",
    motionTitle: "حرکت",
    motionDescription: "ترجیح کاهش حرکت سیستم‌عامل همیشه رعایت می‌شود. این ترجیح افزوده فقط در همین مرورگر ذخیره می‌شود.",
    motionLabel: "کاهش حرکت در CICC",
    integrationTitle: "تنظیمات حساب و مستأجر",
    integrationDescription: "این گزینه‌ها در دسترس نیستند؛ این رابط قرارداد تأییدشده‌ای برای هویت، مستأجر یا سرویس ترجیحات ندارد.",
  },
};

export function SettingsPage() {
  const preferences = useCiccPreferences();
  const id = useId().replaceAll(":", "");
  if (!preferences) return null;

  const { locale, setLocale, reduceMotion, setReduceMotion } = preferences;
  const messages = settingsMessages[locale];

  return (
    <div className={styles.page} lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <header className={styles.pageHeader}>
        <p className={styles.eyebrow}>{messages.eyebrow}</p>
        <h1>{messages.title}</h1>
        <p>{messages.introduction}</p>
      </header>

      <section className={styles.settingsGroup} aria-labelledby={`${id}-preferences`}>
        <h2 id={`${id}-preferences`}>{messages.preferencesGroupTitle}</h2>

        <div className={styles.settingCard}>
          <div className={styles.settingCopy}>
            <h3>{messages.languageTitle}</h3>
            <p id={`${id}-language-description`}>{messages.languageDescription}</p>
          </div>
          <label className={styles.languageControl}>
            <span className={styles.visuallyHidden}>{messages.languageLabel}</span>
            <select
              aria-label={messages.languageLabel}
              aria-describedby={`${id}-language-description`}
              value={locale}
              onChange={(event) => {
                if (isLocale(event.target.value)) setLocale(event.target.value);
              }}
            >
              <option value="en">English</option>
              <option value="ar">العربية</option>
              <option value="fa">فارسی</option>
            </select>
          </label>
        </div>

        <fieldset className={styles.settingCard}>
          <legend>{messages.motionTitle}</legend>
          <div className={styles.settingCopy}>
            <p id={`${id}-motion-description`}>{messages.motionDescription}</p>
          </div>
          <label className={styles.toggleControl}>
            <input
              type="checkbox"
              checked={reduceMotion}
              aria-describedby={`${id}-motion-description`}
              onChange={(event) => setReduceMotion(event.target.checked)}
            />
            <span>{messages.motionLabel}</span>
          </label>
        </fieldset>
      </section>

      <aside className={styles.unavailableNote} aria-labelledby={`${id}-account-settings`}>
        <h2 id={`${id}-account-settings`}>{messages.integrationTitle}</h2>
        <p>{messages.integrationDescription}</p>
      </aside>
    </div>
  );
}
