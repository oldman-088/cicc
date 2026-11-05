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
      description: "This workspace is reserved for operational visibility and service reliability workflows.",
      statusTitle: "Operational telemetry is not connected",
      statusDescription: "No verified health, worker, or queue contract is wired into this frontend. No service status, alert, or throughput is shown as healthy or failing without source data.",
      plannedTitle: "Planned scope — not yet available",
      plannedAreas: [
        "Service and agent health with data freshness",
        "Worker, queue, and task activity when exposed by a provider",
        "Operational alerts and history from verified sources",
      ],
      backToOverview: "Back to workspace overview",
    },
    coordination: {
      eyebrow: "CICC / COORDINATION",
      title: "Agent Coordination",
      description: "This workspace is reserved for agent registry, task assignment, and workflow visibility.",
      statusTitle: "Coordination services are not connected",
      statusDescription: "No verified agent registry or task-management API contract is wired into this frontend. No agents, assignments, approvals, or routing events are invented.",
      plannedTitle: "Planned scope — not yet available",
      plannedAreas: [
        "Agent registry and source-backed status",
        "Task assignment, workflow progress, and approvals",
        "Routing and coordination events with audit context",
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
      description: "مساحة مخصصة للرؤية التشغيلية وموثوقية الخدمات.",
      statusTitle: "القياسات التشغيلية غير متصلة",
      statusDescription: "لا يوجد عقد موثّق للصحة أو العمال أو قوائم الانتظار. لا تُعرض خدمة أو تنبيه أو إنتاجية على أنها سليمة أو متعثرة بلا مصدر بيانات.",
      plannedTitle: "نطاق مخطط — غير متاح بعد",
      plannedAreas: [
        "صحة الخدمات والوكلاء مع حداثة البيانات",
        "نشاط العمال والمهام وقوائم الانتظار عند توفره من المزوّد",
        "التنبيهات والسجل التشغيلي من مصادر موثّقة",
      ],
      backToOverview: "العودة إلى نظرة مساحة العمل",
    },
    coordination: {
      eyebrow: "CICC / التنسيق",
      title: "تنسيق الوكلاء",
      description: "مساحة مخصصة لسجل الوكلاء وإسناد المهام ورؤية سير العمل.",
      statusTitle: "خدمات التنسيق غير متصلة",
      statusDescription: "لا يوجد عقد موثّق لسجل الوكلاء أو إدارة المهام. لا تُختلق وكلاء أو إسنادات أو موافقات أو أحداث توجيه.",
      plannedTitle: "نطاق مخطط — غير متاح بعد",
      plannedAreas: [
        "سجل الوكلاء وحالتهم المدعومة بالمصدر",
        "إسناد المهام وتقدم سير العمل والموافقات",
        "أحداث التوجيه والتنسيق مع سياق التدقيق",
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
      description: "این فضا برای مشاهدهٔ عملیات و پایایی سرویس‌ها در نظر گرفته شده است.",
      statusTitle: "دادهٔ عملیاتی متصل نیست",
      statusDescription: "قرارداد تأییدشدهٔ سلامت، worker یا صف به رابط متصل نیست. بدون منبع داده، سلامت یا خرابی سرویس، هشدار یا توان عملیاتی اعلام نمی‌شود.",
      plannedTitle: "دامنهٔ برنامه‌ریزی‌شده — هنوز در دسترس نیست",
      plannedAreas: [
        "سلامت سرویس و agent همراه با تازگی داده",
        "فعالیت worker، صف و وظیفه در صورت ارائه توسط منبع",
        "هشدار و تاریخچهٔ عملیاتی از منابع تأییدشده",
      ],
      backToOverview: "بازگشت به نمای کلی فضای کاری",
    },
    coordination: {
      eyebrow: "CICC / هماهنگی",
      title: "هماهنگی عامل‌ها",
      description: "این فضا برای فهرست عامل‌ها، تخصیص وظیفه و مشاهدهٔ گردش‌کار در نظر گرفته شده است.",
      statusTitle: "سرویس هماهنگی متصل نیست",
      statusDescription: "قرارداد تأییدشدهٔ API برای فهرست عامل‌ها یا مدیریت وظیفه متصل نیست. عامل، تخصیص، تأیید یا رویداد مسیریابی جعل نمی‌شود.",
      plannedTitle: "دامنهٔ برنامه‌ریزی‌شده — هنوز در دسترس نیست",
      plannedAreas: [
        "فهرست عامل‌ها و وضعیت مبتنی بر منبع",
        "تخصیص وظیفه، پیشرفت گردش‌کار و تأییدها",
        "رویدادهای مسیریابی و هماهنگی همراه با زمینهٔ ممیزی",
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
