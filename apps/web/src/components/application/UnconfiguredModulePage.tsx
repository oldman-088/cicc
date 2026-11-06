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
  integrationTitle?: string;
  integrationGates?: readonly string[];
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
      statusDescription: "The legacy Threat Intelligence dispatcher has explicitly experimental sample handlers. PR #3 also adds standalone experimental relationship routes, but they are not mounted in the CICC host and require host-supplied authentication, tenant, storage, and audit dependencies. Agent 1's sandbox gateway trial uses the legacy dispatcher, not these routes. No actors, indicators, relationships, or live feed health are displayed.",
      integrationTitle: "Integration readiness — pending",
      integrationGates: [
        "Host mount: an owner-approved, versioned read-only CICC route and exact prefix; a package ASGI app is not a mounted endpoint.",
        "Identity: verified authorization and server-derived tenant scope; callers cannot choose a tenant.",
        "Data contract: typed DTOs with live-vs-demo origin, provenance, confidence, freshness, pagination/limits, and error/unavailable behavior.",
        "Storage and audit: approved schema and audit policy, including review of write side effects from GET reads.",
        "Verification: a controlled request to the actual mounted host before rendering records; no fixture fallback.",
      ],
      plannedTitle: "Planned scope — not yet available",
      plannedAreas: [
        "Threat actor, campaign, malware, and technique exploration",
        "Indicator search, correlation, and relationship context",
        "Evidence, provenance, verification, and confidence review",
        "Confirm a frontend-approved host-route or BFF contract with authentication, tenant, and provenance semantics",
      ],
      backToOverview: "Back to workspace overview",
    },
    "vulnerability-intelligence": {
      eyebrow: "CICC / EXPOSURE",
      title: "Vulnerability Intelligence",
      description: "This workspace is reserved for vulnerability exposure, prioritization, and remediation workflows.",
      statusTitle: "Vulnerability API proposal is not mounted",
      statusDescription: "A tested package-level ASGI app supports vulnerability list/detail and CycloneDX VEX, OpenVEX, and SARIF exports, but its OpenAPI contract is still proposed and no CICC host mount, prefix, or principal-to-tenant authorization binding is confirmed. No provider is connected, and no CVEs, severity distributions, EPSS/KEV status, or remediation state are fabricated.",
      plannedTitle: "Planned scope — not yet available",
      plannedAreas: [
        "CVE and affected-product exploration",
        "Risk prioritization and exposure context",
        "Remediation tracking with source and freshness details",
        "Confirm the owner-approved host mount, principal-to-tenant authorization, and export limits before enabling records or VEX/OpenVEX/SARIF",
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
      statusDescription: "يحتوي موزّع استخبارات التهديدات القديم على معالجات عينات تجريبية صراحةً. يضيف PR #3 أيضًا مسارات علاقات تجريبية مستقلة، لكنها غير مركّبة في مضيف CICC وتتطلب من المضيف توفير المصادقة والمستأجر والتخزين والتدقيق. تستخدم تجربة البوابة التي أبلغ عنها الوكيل 1 الموزّع القديم، لا هذه المسارات. لا تُعرض جهات أو مؤشرات أو علاقات أو صحة تغذية مباشرة.",
      integrationTitle: "جاهزية التكامل — بانتظار الحسم",
      integrationGates: [
        "تركيب المضيف: مسار قراءة بإصدار وبادئة CICC محدّدين ومعتمدين من المالك؛ تطبيق ASGI للحزمة ليس نقطة نهاية مركّبة.",
        "الهوية: مصادقة وتفويض موثّقان ونطاق مستأجر يحدده الخادم؛ لا يختار المتصل المستأجر.",
        "عقد البيانات: DTO مكتوب الأنواع يحدد مصدر البيانات الحيّة أو التجريبية والمنشأ والثقة والحداثة والتصفح والحدود وسلوك الأخطاء وعدم الإتاحة.",
        "التخزين والتدقيق: اعتماد المخطط وسياسة التدقيق، بما في ذلك مراجعة آثار الكتابة لطلبات GET.",
        "التحقق: طلب مضبوط إلى المضيف المركّب فعليًا قبل عرض السجلات، من دون بديل من عينات الحزمة.",
      ],
      plannedTitle: "نطاق مخطط — غير متاح بعد",
      plannedAreas: [
        "استكشاف الجهات والحملات والبرمجيات الخبيثة والأساليب",
        "البحث عن المؤشرات وربطها وسياق العلاقات",
        "مراجعة الأدلة والمنشأ والتحقق والثقة",
        "تأكيد عقد واجهة أو BFF معتمد للواجهة الأمامية يحدد المصادقة والمستأجر والمنشأ",
      ],
      backToOverview: "العودة إلى نظرة مساحة العمل",
    },
    "vulnerability-intelligence": {
      eyebrow: "CICC / التعرض",
      title: "استخبارات الثغرات",
      description: "مساحة مخصصة للتعرض للثغرات وتحديد الأولويات وسير عمل المعالجة.",
      statusTitle: "اقتراح API للثغرات غير مركّب",
      statusDescription: "توفّر الحزمة تطبيق ASGI مختبَرًا لقراءة قوائم الثغرات وتفاصيلها وتصدير CycloneDX VEX وOpenVEX وSARIF، لكن عقد OpenAPI ما زال مقترحًا ولم يتأكد تركيب المضيف أو بادئته أو ربط الهوية الموثّقة بالمستأجر. لا يوجد مزوّد متصل، ولا تُختلق ثغرات CVE أو توزيعات الشدة أو حالة EPSS/KEV أو حالة المعالجة.",
      plannedTitle: "نطاق مخطط — غير متاح بعد",
      plannedAreas: [
        "استكشاف CVE والمنتجات المتأثرة",
        "تحديد الأولويات وسياق التعرض",
        "تتبع المعالجة مع المصدر وحداثة البيانات",
        "تأكيد تركيب المضيف المعتمد وربط الهوية الموثّقة بالمستأجر وحدود التصدير قبل إتاحة السجلات أو VEX/OpenVEX/SARIF",
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
      statusDescription: "پخش‌کنندهٔ قدیمی اطلاعات تهدید، گرداننده‌های نمونهٔ صریحاً آزمایشی دارد. PR #3 مسیرهای آزمایشی مستقلی برای روابط نیز اضافه کرده است، اما این مسیرها روی میزبان CICC نصب نشده‌اند و به احراز هویت، تعیین مستأجر، ذخیره‌سازی و ثبت رویدادهایی نیاز دارند که میزبان باید فراهم کند. آزمون دروازه‌ای گزارش‌شده از سوی عامل ۱ از پخش‌کنندهٔ قدیمی استفاده می‌کند، نه این مسیرها. هیچ عامل، شاخص، رابطه یا وضعیت زندهٔ خوراک نمایش داده نمی‌شود.",
      integrationTitle: "آمادگی یکپارچه‌سازی — در انتظار تصمیم",
      integrationGates: [
        "نصب در میزبان: مسیر خواندن نسخه‌دار و پیشوند دقیق CICC با تأیید مالک؛ برنامهٔ ASGI بسته به‌تنهایی نقطه‌پایان نصب‌شده نیست.",
        "هویت: احراز هویت و مجوزدهی معتبر، و محدودهٔ مستأجر تعیین‌شده در سرور؛ درخواست‌کننده نمی‌تواند مستأجر را انتخاب کند.",
        "قرارداد داده: DTO تایپ‌شده برای مبدأ زنده/آزمایشی، منشأ، اطمینان، تازگی، صفحه‌بندی/محدودیت‌ها و رفتار خطا یا عدم دسترسی.",
        "ذخیره‌سازی و ممیزی: تأیید طرح‌واره و سیاست ممیزی، از جمله بررسی اثرهای نوشتن در درخواست‌های GET.",
        "راستی‌آزمایی: پیش از نمایش رکورد، درخواست کنترل‌شده به میزبان واقعاً نصب‌شده انجام شود؛ بدون جایگزینی با نمونه‌های بسته.",
      ],
      plannedTitle: "دامنهٔ برنامه‌ریزی‌شده — هنوز در دسترس نیست",
      plannedAreas: [
        "کاوش عامل‌های تهدید، کارزارها، بدافزار و روش‌ها",
        "جست‌وجوی شاخص‌ها، هم‌بستگی و زمینهٔ پیوندها",
        "بررسی شواهد، منشأ، تأیید و میزان اطمینان",
        "تأیید قرارداد مسیر میزبانی‌شده یا BFF با معناشناسی احراز هویت، مستأجر و منشأ",
      ],
      backToOverview: "بازگشت به نمای کلی فضای کاری",
    },
    "vulnerability-intelligence": {
      eyebrow: "CICC / مواجهه",
      title: "اطلاعات آسیب‌پذیری",
      description: "این فضا برای بررسی مواجهه با آسیب‌پذیری، اولویت‌بندی و گردش‌کار اصلاح در نظر گرفته شده است.",
      statusTitle: "پیشنهاد API آسیب‌پذیری نصب نشده است",
      statusDescription: "بسته یک برنامهٔ ASGI آزمایش‌شده برای خواندن فهرست و جزئیات آسیب‌پذیری و خروجی‌های CycloneDX VEX، OpenVEX و SARIF دارد؛ بااین‌حال قرارداد OpenAPI هنوز پیشنهادی است و نصب روی میزبان CICC، پیشوند مسیر یا پیوند هویت احراز‌شده به مستأجر تأیید نشده است. منبعی متصل نیست و CVE، توزیع شدت، وضعیت EPSS/KEV یا وضعیت اصلاح جعل نمی‌شود.",
      plannedTitle: "دامنهٔ برنامه‌ریزی‌شده — هنوز در دسترس نیست",
      plannedAreas: [
        "کاوش CVE و محصولات متأثر",
        "اولویت‌بندی ریسک و زمینهٔ مواجهه",
        "پیگیری اصلاح با منبع و تازگی داده",
        "تأیید نصب میزبان مورد پذیرش مالک، مجوزدهی هویت احراز‌شده به مستأجر و محدودیت‌های خروجی پیش از فعال‌سازی رکوردها یا VEX/OpenVEX/SARIF",
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

      {messages.integrationTitle && messages.integrationGates && (
        <section className={styles.integrationScope} aria-labelledby={`${id}-integration-title`}>
          <h2 id={`${id}-integration-title`}>{messages.integrationTitle}</h2>
          <ul>
            {messages.integrationGates.map((gate) => <li key={gate}>{gate}</li>)}
          </ul>
        </section>
      )}

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
