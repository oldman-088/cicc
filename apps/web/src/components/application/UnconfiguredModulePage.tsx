"use client";

import Link from "next/link";
import { useId } from "react";
import type { Locale } from "./localization";
import { useCiccLocale } from "./CiccApplication";
import styles from "./UnconfiguredModulePage.module.css";

type UnconfiguredModuleId =
  | "threat-intelligence"
  | "vulnerability-intelligence"
  | "system-health"
  | "coordination";

type ModuleCopy = {
  eyebrow: string;
  title: string;
  description: string;
  statusTitle: string;
  statusDescription: string;
  plannedTitle: string;
  plannedAreas: readonly string[];
  backToOverview: string;
};

const moduleMessages: Record<Locale, Record<UnconfiguredModuleId, ModuleCopy>> = {
  en: {
    "threat-intelligence": {
      eyebrow: "CICC / INTELLIGENCE",
      title: "Threat Intelligence",
      description: "This workspace is reserved for evidence-led threat analysis and investigation workflows.",
      statusTitle: "Threat data is not connected",
      statusDescription: "No verified threat-intelligence API contract or provider is wired into this frontend. No actors, indicators, counts, or feed health are fabricated.",
      plannedTitle: "Planned scope — not yet available",
      plannedAreas: [
        "Threat actor, campaign, malware, and technique exploration",
        "Indicator search, correlation, and relationship context",
        "Evidence, provenance, verification, and confidence review",
      ],
      backToOverview: "Back to workspace overview",
    },
    "vulnerability-intelligence": {
      eyebrow: "CICC / EXPOSURE",
      title: "Vulnerability Intelligence",
      description: "This workspace is reserved for vulnerability exposure, prioritization, and remediation workflows.",
      statusTitle: "Vulnerability data is not connected",
      statusDescription: "No verified vulnerability API contract or provider is wired into this frontend. No CVEs, severity distributions, EPSS/KEV status, or remediation state are fabricated.",
      plannedTitle: "Planned scope — not yet available",
      plannedAreas: [
        "CVE and affected-product exploration",
        "Risk prioritization and exposure context",
        "Remediation tracking with source and freshness details",
      ],
      backToOverview: "Back to workspace overview",
    },
    "system-health": {
      eyebrow: "CICC / OPERATIONS",
      title: "System Health",
      description: "This workspace displays operational values only when its server-side provider is configured and returns a valid response.",
      statusTitle: "Operations provider is not available",
      statusDescription: "The read-only adapter is present, but this deployment has no valid provider response. No status, alert, or throughput is inferred from the absence of data.",
      plannedTitle: "Available read-only views",
      plannedAreas: [
        "Provider-reported service and module statuses with timestamps",
        "Operational metrics and alerts when returned by the provider",
        "Worker-liveness records as reported by the API",
      ],
      backToOverview: "Back to workspace overview",
    },
    coordination: {
      eyebrow: "CICC / COORDINATION",
      title: "Agent Coordination",
      description: "This workspace displays registry, task, metric, and event data only when its server-side provider is configured.",
      statusTitle: "Coordination provider is not available",
      statusDescription: "The read-only adapter is present, but this deployment has no valid provider response. No agents, assignments, approvals, or routing outcomes are invented.",
      plannedTitle: "Available read-only views",
      plannedAreas: [
        "Agent registry and provider-reported status",
        "Task records, state filters, and coordination metrics",
        "Webhook event records with provider-supplied context",
      ],
      backToOverview: "Back to workspace overview",
    },
  },
  ar: {
    "threat-intelligence": {
      eyebrow: "CICC / الاستخبارات",
      title: "استخبارات التهديدات",
      description: "مساحة مخصصة لتحليل التهديدات القائم على الأدلة وسير عمل التحقيق.",
      statusTitle: "بيانات التهديدات غير متصلة",
      statusDescription: "لا يوجد في هذه الواجهة مزوّد أو عقد API موثّق لاستخبارات التهديدات. لا تُختلق جهات أو مؤشرات أو أعداد أو حالة تغذية.",
      plannedTitle: "نطاق مخطط — غير متاح بعد",
      plannedAreas: [
        "استكشاف الجهات والحملات والبرمجيات الخبيثة والأساليب",
        "البحث عن المؤشرات وربطها وسياق العلاقات",
        "مراجعة الأدلة والمنشأ والتحقق والثقة",
      ],
      backToOverview: "العودة إلى نظرة مساحة العمل",
    },
    "vulnerability-intelligence": {
      eyebrow: "CICC / التعرض",
      title: "استخبارات الثغرات",
      description: "مساحة مخصصة للتعرض للثغرات وتحديد الأولويات وسير عمل المعالجة.",
      statusTitle: "بيانات الثغرات غير متصلة",
      statusDescription: "لا يوجد مزوّد أو عقد API موثّق للثغرات. لا تُختلق ثغرات CVE أو توزيعات الشدة أو حالة EPSS/KEV أو حالة المعالجة.",
      plannedTitle: "نطاق مخطط — غير متاح بعد",
      plannedAreas: [
        "استكشاف CVE والمنتجات المتأثرة",
        "تحديد الأولويات وسياق التعرض",
        "تتبع المعالجة مع المصدر وحداثة البيانات",
      ],
      backToOverview: "العودة إلى نظرة مساحة العمل",
    },
    "system-health": {
      eyebrow: "CICC / العمليات",
      title: "سلامة النظام",
      description: "تعرض هذه المساحة القيم التشغيلية فقط عند ضبط المزوّد الخادمي وإرجاعه استجابة صالحة.",
      statusTitle: "مزوّد العمليات غير متاح",
      statusDescription: "المحوّل للقراءة فقط موجود، لكن هذا النشر لا يملك استجابة صالحة من المزوّد. لا تُستنتج حالة أو تنبيه أو إنتاجية من غياب البيانات.",
      plannedTitle: "عروض متاحة للقراءة فقط",
      plannedAreas: [
        "حالات الخدمات والوحدات والطوابع الزمنية كما أبلغ عنها المزوّد",
        "المقاييس والتنبيهات التشغيلية عند إعادتها من المزوّد",
        "سجلات حيوية العمال كما يعيدها API",
      ],
      backToOverview: "العودة إلى نظرة مساحة العمل",
    },
    coordination: {
      eyebrow: "CICC / التنسيق",
      title: "تنسيق الوكلاء",
      description: "تعرض هذه المساحة السجل والمهام والمقاييس والأحداث فقط عند ضبط المزوّد الخادمي.",
      statusTitle: "مزوّد التنسيق غير متاح",
      statusDescription: "المحوّل للقراءة فقط موجود، لكن هذا النشر لا يملك استجابة صالحة من المزوّد. لا تُختلق وكلاء أو إسنادات أو موافقات أو نتائج توجيه.",
      plannedTitle: "عروض متاحة للقراءة فقط",
      plannedAreas: [
        "سجل الوكلاء والحالة التي أبلغ عنها المزوّد",
        "سجلات المهام وتصفية الحالات ومقاييس التنسيق",
        "سجلات أحداث الويب هوك مع السياق الذي يقدمه المزوّد",
      ],
      backToOverview: "العودة إلى نظرة مساحة العمل",
    },
  },
  fa: {
    "threat-intelligence": {
      eyebrow: "CICC / اطلاعات تهدید",
      title: "اطلاعات تهدید",
      description: "این فضا برای تحلیل مبتنی بر شواهد و گردش‌کارهای بررسی تهدید در نظر گرفته شده است.",
      statusTitle: "دادهٔ تهدید متصل نیست",
      statusDescription: "در این رابط قرارداد تأییدشدهٔ API یا منبع دادهٔ اطلاعات تهدید وجود ندارد. عامل، شاخص، تعداد یا سلامت خوراکی جعل نمی‌شود.",
      plannedTitle: "دامنهٔ برنامه‌ریزی‌شده — هنوز در دسترس نیست",
      plannedAreas: [
        "کاوش عامل‌های تهدید، کارزارها، بدافزار و روش‌ها",
        "جست‌وجوی شاخص‌ها، هم‌بستگی و زمینهٔ پیوندها",
        "بررسی شواهد، منشأ، تأیید و میزان اطمینان",
      ],
      backToOverview: "بازگشت به نمای کلی فضای کاری",
    },
    "vulnerability-intelligence": {
      eyebrow: "CICC / مواجهه",
      title: "اطلاعات آسیب‌پذیری",
      description: "این فضا برای بررسی مواجهه با آسیب‌پذیری، اولویت‌بندی و گردش‌کار اصلاح در نظر گرفته شده است.",
      statusTitle: "دادهٔ آسیب‌پذیری متصل نیست",
      statusDescription: "قرارداد تأییدشدهٔ API یا منبع آسیب‌پذیری متصل نیست. CVE، توزیع شدت، وضعیت EPSS/KEV یا وضعیت اصلاح جعل نمی‌شود.",
      plannedTitle: "دامنهٔ برنامه‌ریزی‌شده — هنوز در دسترس نیست",
      plannedAreas: [
        "کاوش CVE و محصولات متأثر",
        "اولویت‌بندی ریسک و زمینهٔ مواجهه",
        "پیگیری اصلاح با منبع و تازگی داده",
      ],
      backToOverview: "بازگشت به نمای کلی فضای کاری",
    },
    "system-health": {
      eyebrow: "CICC / عملیات",
      title: "سلامت سامانه",
      description: "این فضا فقط زمانی دادهٔ عملیاتی نشان می‌دهد که منبع سمت‌سرور پیکربندی شده و پاسخ معتبر برگرداند.",
      statusTitle: "منبع عملیات در دسترس نیست",
      statusDescription: "آداپتور فقط‌خواندنی موجود است، اما این استقرار پاسخ معتبر از منبع ندارد. از نبود داده، وضعیت، هشدار یا توان عملیاتی استنباط نمی‌شود.",
      plannedTitle: "نماهای فقط‌خواندنی موجود",
      plannedAreas: [
        "وضعیت سرویس و ماژول و مُهر زمانی گزارش‌شده از منبع",
        "معیارها و هشدارهای عملیاتی در صورت بازگشت از منبع",
        "رکوردهای زنده‌بودن worker طبق گزارش API",
      ],
      backToOverview: "بازگشت به نمای کلی فضای کاری",
    },
    coordination: {
      eyebrow: "CICC / هماهنگی",
      title: "هماهنگی عامل‌ها",
      description: "این فضا فقط در صورت پیکربندی منبع سمت‌سرور، دادهٔ فهرست، وظیفه، معیار و رویداد را نشان می‌دهد.",
      statusTitle: "منبع هماهنگی در دسترس نیست",
      statusDescription: "آداپتور فقط‌خواندنی موجود است، اما این استقرار پاسخ معتبر از منبع ندارد. عامل، تخصیص، تأیید یا نتیجهٔ مسیریابی جعل نمی‌شود.",
      plannedTitle: "نماهای فقط‌خواندنی موجود",
      plannedAreas: [
        "فهرست عامل‌ها و وضعیت گزارش‌شده از منبع",
        "رکورد وظیفه، فیلتر وضعیت و معیارهای هماهنگی",
        "رویدادهای وب‌هوک با زمینهٔ ارائه‌شده از منبع",
      ],
      backToOverview: "بازگشت به نمای کلی فضای کاری",
    },
  },
};

export function UnconfiguredModulePage({ moduleId }: { moduleId: UnconfiguredModuleId }) {
  const workspaceLocale = useCiccLocale();
  const locale = workspaceLocale?.locale ?? "en";
  const messages = moduleMessages[locale][moduleId];
  const id = useId().replaceAll(":", "");

  return (
    <div className={styles.page} lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <header className={styles.pageHeader}>
        <p className={styles.eyebrow}>{messages.eyebrow}</p>
        <h1>{messages.title}</h1>
        <p>{messages.description}</p>
      </header>

      <section className={styles.unconfiguredCard} aria-labelledby={`${id}-status-title`}>
        <span className={styles.statusGlyph} aria-hidden="true">
          <svg viewBox="0 0 24 24" focusable="false">
            <path d="M12 3.5 21 20H3z" />
            <path d="M12 9v5m0 3h.01" />
          </svg>
        </span>
        <div>
          <h2 id={`${id}-status-title`}>{messages.statusTitle}</h2>
          <p>{messages.statusDescription}</p>
        </div>
      </section>

      <section className={styles.plannedScope} aria-labelledby={`${id}-planned-title`}>
        <h2 id={`${id}-planned-title`}>{messages.plannedTitle}</h2>
        <ul>
          {messages.plannedAreas.map((area) => <li key={area}>{area}</li>)}
        </ul>
      </section>

      <Link className={styles.backLink} href="/">
        <span className={styles.backArrow} aria-hidden="true">←</span>
        {messages.backToOverview}
      </Link>
    </div>
  );
}
