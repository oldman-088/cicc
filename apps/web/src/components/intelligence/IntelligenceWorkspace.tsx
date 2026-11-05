"use client";

import { useCiccLocale } from "../application/CiccApplication";
import styles from "./IntelligenceWorkspace.module.css";

type Kind = "threat" | "vulnerability";
const copy = {
  en: {
    threat: { eyebrow: "CICC / INTELLIGENCE", title: "Threat Intelligence", unavailable: "Threat data is not connected. No verified, mounted threat-intelligence provider is bound to this frontend, so no actors, indicators, counts, or feed health are shown.", search: "Search indicators, actors, campaigns (disabled)", filter: "Entity type (disabled)", detail: "Select a record to inspect evidence, provenance, verification, and confidence. Records will appear here only from a verified provider.", planned: ["Threat actor, campaign, malware, and technique exploration", "Indicator search, correlation, and relationship context", "Evidence, provenance, verification, and confidence review"] },
    vulnerability: { eyebrow: "CICC / EXPOSURE", title: "Vulnerability Intelligence", unavailable: "Vulnerability data is not connected. No verified, mounted vulnerability provider is bound to this frontend, so no CVEs, severity distributions, EPSS/KEV status, or remediation states are shown.", search: "Search CVEs and affected products (disabled)", filter: "Severity (disabled)", detail: "Select a record to inspect affected products, prioritization, provenance, and freshness. Records will appear here only from a verified provider.", planned: ["CVE and affected-product exploration", "Risk prioritization and exposure context", "Remediation tracking with source and freshness details"] },
    structure: "Workspace structure — disabled until a provider is connected", plannedTitle: "Planned scope — not yet available",
  },
  ar: {
    threat: { eyebrow: "CICC / الاستخبارات", title: "استخبارات التهديدات", unavailable: "بيانات التهديدات غير متصلة. لا يوجد مزوّد استخبارات تهديدات موثّق ومثبّت مرتبط بهذه الواجهة، لذا لا تُعرض جهات أو مؤشرات أو أعداد أو حالة تغذية.", search: "بحث المؤشرات والجهات والحملات (معطّل)", filter: "نوع الكيان (معطّل)", detail: "اختر سجلاً لفحص الأدلة والمنشأ والتحقق والثقة. ستظهر السجلات هنا فقط من مزوّد موثّق.", planned: ["استكشاف الجهات والحملات والبرمجيات الخبيثة والأساليب", "البحث عن المؤشرات وربطها وسياق العلاقات", "مراجعة الأدلة والمنشأ والتحقق والثقة"] },
    vulnerability: { eyebrow: "CICC / التعرض", title: "استخبارات الثغرات", unavailable: "بيانات الثغرات غير متصلة. لا يوجد مزوّد ثغرات موثّق ومثبّت مرتبط بهذه الواجهة، لذا لا تُعرض ثغرات أو توزيعات شدة أو حالة EPSS/KEV أو معالجة.", search: "بحث CVE والمنتجات المتأثرة (معطّل)", filter: "الشدة (معطّلة)", detail: "اختر سجلاً لفحص المنتجات المتأثرة والأولوية والمنشأ والحداثة. ستظهر السجلات هنا فقط من مزوّد موثّق.", planned: ["استكشاف CVE والمنتجات المتأثرة", "تحديد الأولويات وسياق التعرض", "تتبع المعالجة مع المصدر وحداثة البيانات"] },
    structure: "بنية مساحة العمل — معطلة حتى اتصال مزوّد", plannedTitle: "نطاق مخطط — غير متاح بعد",
  },
  fa: {
    threat: { eyebrow: "CICC / اطلاعات تهدید", title: "اطلاعات تهدید", unavailable: "دادهٔ تهدید متصل نیست. منبع اطلاعات تهدید تأییدشده و نصب‌شده‌ای به این رابط متصل نیست، بنابراین عامل، شاخص، تعداد یا سلامت خوراکی نمایش داده نمی‌شود.", search: "جست‌وجوی شاخص‌ها، عامل‌ها و کارزارها (غیرفعال)", filter: "نوع موجودیت (غیرفعال)", detail: "سابقه‌ای را برای بررسی شواهد، منشأ، تأیید و اطمینان انتخاب کنید. سوابق فقط از منبع تأییدشده در اینجا ظاهر می‌شوند.", planned: ["کاوش عامل‌های تهدید، کارزارها، بدافزار و روش‌ها", "جست‌وجوی شاخص‌ها، هم‌بستگی و زمینهٔ پیوندها", "بررسی شواهد، منشأ، تأیید و میزان اطمینان"] },
    vulnerability: { eyebrow: "CICC / مواجهه", title: "اطلاعات آسیب‌پذیری", unavailable: "دادهٔ آسیب‌پذیری متصل نیست. منبع آسیب‌پذیری تأییدشده و نصب‌شده‌ای متصل نیست، بنابراین CVE، توزیع شدت، وضعیت EPSS/KEV یا اصلاح نمایش داده نمی‌شود.", search: "جست‌وجوی CVE و محصولات آسیب‌دیده (غیرفعال)", filter: "شدت (غیرفعال)", detail: "سابقه‌ای را برای بررسی محصولات آسیب‌دیده، اولویت‌بندی، منشأ و تازگی انتخاب کنید. سوابق فقط از منبع تأییدشده ظاهر می‌شوند.", planned: ["استكشاف CVE والمنتجات المتأثرة", "اولویت‌بندی ریسک و زمینهٔ مواجهه", "پیگیری اصلاح با جزئیات منبع و تازگی"] },
    structure: "ساختار فضای کاری — تا اتصال منبع غیرفعال است", plannedTitle: "دامنهٔ برنامه‌ریزی‌شده — هنوز در دسترس نیست",
  },
} as const;

export function IntelligenceWorkspace({ kind }: { kind: Kind }) {
  const locale = useCiccLocale()?.locale ?? "en";
  const all = copy[locale];
  const m = all[kind];
  return (
    <div className={styles.page} lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <header>
        <p className={styles.eyebrow}>{m.eyebrow}</p>
        <h1>{m.title}</h1>
        <p role="note">{m.unavailable}</p>
      </header>
      <section aria-label={all.structure} className={styles.panel}>
        <h2>{all.structure}</h2>
        <div className={styles.filters}>
          <label>{m.search}<input type="search" disabled aria-disabled="true" aria-label={m.search} /></label>
          <label>{m.filter}<select disabled aria-disabled="true" aria-label={m.filter}><option>{m.filter}</option></select></label>
        </div>
        <div className={styles.layout}>
          <p>{m.unavailable}</p>
          <aside aria-label={m.detail}><p>{m.detail}</p></aside>
        </div>
      </section>
      <section className={styles.panel}>
        <h2>{all.plannedTitle}</h2>
        <ul>{m.planned.map((item) => <li key={item}>{item}</li>)}</ul>
      </section>
    </div>
  );
}
