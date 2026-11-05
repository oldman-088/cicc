"use client";

import Link from "next/link";
import { useId } from "react";
import type { Locale } from "../application/localization";
import { useCiccLocale } from "../application/CiccApplication";
import styles from "./WorkspaceOverview.module.css";

type WorkspaceOverviewProps = {
  demoMode: boolean;
};

type DestinationCopy = {
  title: string;
  description: string;
  openAction: string;
  unavailableBadge: string;
};

type OverviewMessages = {
  eyebrow: string;
  title: string;
  introduction: string;
  scopeLabel: string;
  integrationTitleDemo: string;
  integrationDescriptionDemo: string;
  integrationTitleUnavailable: string;
  integrationDescriptionUnavailable: string;
  workflowEyebrow: string;
  workflowTitle: string;
  workflowDescription: string;
  demoBadge: string;
  dataIntegrityTitle: string;
  dataIntegrityDescription: string;
  sourceFreshnessTitle: string;
  sourceFreshnessDescription: string;
  sourceFreshnessDemoDescription: string;
  recentEventsTitle: string;
  recentEventsDescription: string;
  recentEventsDemoDescription: string;
  eventDestinationsLabel: string;
  commandTheater: DestinationCopy;
  threatIntelligence: DestinationCopy;
  vulnerabilityIntelligence: DestinationCopy;
  systemHealth: DestinationCopy;
  coordination: DestinationCopy;
};

const overviewMessages: Record<Locale, OverviewMessages> = {
  en: {
    eyebrow: "CICC / WORKSPACE",
    title: "Workspace overview",
    introduction: "A transparent starting point for the frontend modules in this build.",
    scopeLabel: "Frontend workspace",
    integrationTitleDemo: "Synthetic development sample only",
    integrationDescriptionDemo: "Command Theater can load isolated synthetic records in development. They are visibly marked as synthetic and are never presented as live intelligence.",
    integrationTitleUnavailable: "No provider is configured in this deployment",
    integrationDescriptionUnavailable: "System Health and Coordination have read-only server-side adapters, but no provider is configured by default. Without a valid response, they show unavailable states; Threat Intelligence, Vulnerability Intelligence, and production Command Theater data remain unconnected.",
    workflowEyebrow: "WORKSPACE MODULES",
    workflowTitle: "Explore the workspace",
    workflowDescription: "Routes are navigable; each module states plainly whether its data integration is connected.",
    demoBadge: "Synthetic demo in development",
    dataIntegrityTitle: "Data integrity",
    dataIntegrityDescription: "A visible page is not evidence of live data. Unconfigured, unavailable, cached, and synthetic states remain distinct; no live counts or service health are inferred.",
    sourceFreshnessTitle: "Data sources and freshness",
    sourceFreshnessDescription: "System Health and Coordination show provider timestamps or cache metadata only when returned by the server-side API. This overview does not aggregate their freshness, and the other domains have no production data source.",
    sourceFreshnessDemoDescription: "The Command Theater sample is synthetic, not live intelligence, and has no production source timestamp.",
    recentEventsTitle: "Recent events",
    recentEventsDescription: "This overview does not aggregate operational events. Coordination and System Health show only events returned by their configured provider; no events are fabricated here.",
    recentEventsDemoDescription: "No operational event feed is configured; synthetic graph fixtures are not presented as recent events.",
    eventDestinationsLabel: "Related activity workspaces",
    commandTheater: {
      title: "Command Theater",
      description: "Explore entity relationships with an accessible 2D map and an optional 3D view. The UI is ready; production data requires a verified provider.",
      openAction: "Open Command Theater",
      unavailableBadge: "Data provider required",
    },
    threatIntelligence: {
      title: "Threat Intelligence",
      description: "Threat analysis and investigation workspace. Its page explicitly lists the planned scope and missing provider contract.",
      openAction: "Open Threat Intelligence",
      unavailableBadge: "Not connected",
    },
    vulnerabilityIntelligence: {
      title: "Vulnerability Intelligence",
      description: "Exposure and remediation workspace. No CVE records, scores, or status are displayed without a verified source.",
      openAction: "Open Vulnerability Intelligence",
      unavailableBadge: "Not connected",
    },
    systemHealth: {
      title: "System Health",
      description: "Read-only operational views use a server-side adapter; provider values appear only when this trusted deployment is configured and the API returns valid data.",
      openAction: "Open System Health",
      unavailableBadge: "Not connected",
    },
    coordination: {
      title: "Agent Coordination",
      description: "Read-only agent, task, metric, and event views use a server-side adapter and remain unavailable until the trusted deployment is configured.",
      openAction: "Open Agent Coordination",
      unavailableBadge: "Not connected",
    },
  },
  ar: {
    eyebrow: "CICC / مساحة العمل",
    title: "نظرة عامة على مساحة العمل",
    introduction: "نقطة بداية شفافة لوحدات الواجهة الموجودة في هذا الإصدار.",
    scopeLabel: "مساحة الواجهة الأمامية",
    integrationTitleDemo: "بيانات تطوير اصطناعية فقط",
    integrationDescriptionDemo: "يمكن لمسرح القيادة تحميل سجلات اصطناعية معزولة أثناء التطوير. وتُوسم بوضوح بأنها اصطناعية ولا تُعرض مطلقاً كمعلومات حية.",
    integrationTitleUnavailable: "لم يُضبط مزوّد في هذا النشر",
    integrationDescriptionUnavailable: "تملك سلامة النظام والتنسيق محوّلات خادمية للقراءة فقط، لكن لا يُضبط مزوّد افتراضياً. بلا استجابة صالحة ستعرضان حالة عدم التوفر؛ وتظل استخبارات التهديدات والثغرات وبيانات الإنتاج لمسرح القيادة غير متصلة.",
    workflowEyebrow: "وحدات مساحة العمل",
    workflowTitle: "استكشف مساحة العمل",
    workflowDescription: "يمكن فتح المسارات، وتوضح كل وحدة صراحةً ما إذا كان تكامل بياناتها متصلاً.",
    demoBadge: "عرض اصطناعي في بيئة التطوير",
    dataIntegrityTitle: "سلامة البيانات",
    dataIntegrityDescription: "وجود صفحة لا يعني وجود بيانات حية. تبقى الحالات غير المهيأة وغير المتاحة والمخزنة مؤقتاً والاصطناعية متميزة؛ ولا تُستنتج أعداد حية أو سلامة خدمات.",
    sourceFreshnessTitle: "مصادر البيانات وحداثتها",
    sourceFreshnessDescription: "تعرض سلامة النظام والتنسيق الطوابع الزمنية أو بيانات التخزين المؤقت التي يعيدها API الخادمي فقط. لا تجمع هذه النظرة حداثة بياناتهما، ولا تملك المجالات الأخرى مصدراً إنتاجياً.",
    sourceFreshnessDemoDescription: "عينة مسرح القيادة اصطناعية وليست استخبارات حية، ولا تحمل طابعاً زمنياً لمصدر إنتاجي.",
    recentEventsTitle: "الأحداث الأخيرة",
    recentEventsDescription: "لا تجمع هذه النظرة الأحداث التشغيلية. تعرض صفحتا التنسيق وسلامة النظام الأحداث التي يعيدها المزوّد المضبوط فقط؛ ولا تُختلق أحداث هنا.",
    recentEventsDemoDescription: "لا يوجد موجز أحداث تشغيلية؛ ولا تُعرض عينات الرسم الاصطناعية كأحداث حديثة.",
    eventDestinationsLabel: "مساحات العمل المرتبطة بالنشاط",
    commandTheater: {
      title: "مسرح القيادة",
      description: "استكشف علاقات الكيانات بخريطة ثنائية الأبعاد ميسّرة وعرض ثلاثي الأبعاد اختياري. الواجهة جاهزة؛ وبيانات الإنتاج تتطلب مزوّداً موثّقاً.",
      openAction: "فتح مسرح القيادة",
      unavailableBadge: "يتطلب مزوّد بيانات",
    },
    threatIntelligence: {
      title: "استخبارات التهديدات",
      description: "مساحة لتحليل التهديدات والتحقيق. تعرض صفحتها النطاق المخطط وعقد المزوّد المفقود بوضوح.",
      openAction: "فتح استخبارات التهديدات",
      unavailableBadge: "غير متصل",
    },
    vulnerabilityIntelligence: {
      title: "استخبارات الثغرات",
      description: "مساحة للتعرض للثغرات والمعالجة. لا تُعرض سجلات CVE أو درجات أو حالات بلا مصدر موثّق.",
      openAction: "فتح استخبارات الثغرات",
      unavailableBadge: "غير متصل",
    },
    systemHealth: {
      title: "سلامة النظام",
      description: "تستخدم العروض التشغيلية للقراءة فقط محوّلاً خادمياً؛ ولا تظهر القيم إلا عند ضبط هذا النشر الموثوق وإرجاع API بيانات صالحة.",
      openAction: "فتح سلامة النظام",
      unavailableBadge: "غير متصل",
    },
    coordination: {
      title: "تنسيق الوكلاء",
      description: "تستخدم عروض الوكلاء والمهام والمقاييس والأحداث للقراءة فقط محوّلاً خادمياً، وتظل غير متاحة حتى ضبط النشر الموثوق.",
      openAction: "فتح تنسيق الوكلاء",
      unavailableBadge: "غير متصل",
    },
  },
  fa: {
    eyebrow: "CICC / فضای کاری",
    title: "نمای کلی فضای کاری",
    introduction: "نقطهٔ شروعی شفاف برای ماژول‌های رابط کاربری موجود در این ساخت.",
    scopeLabel: "فضای رابط کاربری",
    integrationTitleDemo: "فقط نمونهٔ ساختگی توسعه",
    integrationDescriptionDemo: "تالار فرماندهی می‌تواند هنگام توسعه رکوردهای ساختگی جداگانه بارگیری کند. این رکوردها آشکارا ساختگی علامت‌گذاری می‌شوند و هرگز اطلاعات زنده معرفی نمی‌شوند.",
    integrationTitleUnavailable: "در این استقرار منبعی پیکربندی نشده است",
    integrationDescriptionUnavailable: "سلامت سامانه و هماهنگی دارای آداپتور سمت‌سرور فقط‌خواندنی هستند، اما به‌طور پیش‌فرض منبعی پیکربندی نشده است. بدون پاسخ معتبر وضعیت عدم دسترسی نشان می‌دهند؛ اطلاعات تهدید، آسیب‌پذیری و دادهٔ تولیدی تالار فرماندهی همچنان متصل نیستند.",
    workflowEyebrow: "ماژول‌های فضای کاری",
    workflowTitle: "کاوش در فضای کاری",
    workflowDescription: "مسیرها قابل پیمایش‌اند و هر ماژول روشن می‌گوید که آیا اتصال داده دارد یا نه.",
    demoBadge: "نمای ساختگی در محیط توسعه",
    dataIntegrityTitle: "درستی داده‌ها",
    dataIntegrityDescription: "وجود صفحه به‌معنای دادهٔ زنده نیست. وضعیت‌های پیکربندی‌نشده، ناموجود، کش‌شده و ساختگی متمایزند؛ تعداد زنده یا سلامت سرویس حدس زده نمی‌شود.",
    sourceFreshnessTitle: "منبع داده و تازگی",
    sourceFreshnessDescription: "سلامت سامانه و هماهنگی فقط مُهر زمانی یا فرادادهٔ کشِ بازگشتی از API سمت‌سرور را نشان می‌دهند. این نمای کلی تازگی آن‌ها را تجمیع نمی‌کند و حوزه‌های دیگر منبع دادهٔ تولیدی ندارند.",
    sourceFreshnessDemoDescription: "نمونهٔ تالار فرماندهی ساختگی است، اطلاعات زنده نیست و مُهر زمانی منبع تولیدی ندارد.",
    recentEventsTitle: "رویدادهای اخیر",
    recentEventsDescription: "این نمای کلی رویدادهای عملیاتی را تجمیع نمی‌کند. هماهنگی و سلامت سامانه فقط رویدادهای بازگشتی از منبع پیکربندی‌شده را نشان می‌دهند؛ رویدادی جعل نمی‌شود.",
    recentEventsDemoDescription: "جریان رویداد عملیاتی تنظیم نشده است؛ نمونه‌های ساختگی نمودار به‌عنوان رویداد اخیر نشان داده نمی‌شوند.",
    eventDestinationsLabel: "فضاهای کاری مرتبط با فعالیت",
    commandTheater: {
      title: "تالار فرماندهی",
      description: "پیوند موجودیت‌ها را با نقشهٔ دوبعدی دسترس‌پذیر و نمای سه‌بعدی اختیاری ببینید. رابط آماده است؛ دادهٔ عملیاتی به منبع تأییدشده نیاز دارد.",
      openAction: "بازکردن تالار فرماندهی",
      unavailableBadge: "نیازمند منبع داده",
    },
    threatIntelligence: {
      title: "اطلاعات تهدید",
      description: "فضای تحلیل تهدید و بررسی. صفحه دامنهٔ برنامه‌ریزی‌شده و قرارداد منبعِ متصل‌نشده را روشن بیان می‌کند.",
      openAction: "بازکردن اطلاعات تهدید",
      unavailableBadge: "متصل نیست",
    },
    vulnerabilityIntelligence: {
      title: "اطلاعات آسیب‌پذیری",
      description: "فضای مواجهه و اصلاح. بدون منبع تأییدشده، رکورد CVE، امتیاز یا وضعیت نمایش داده نمی‌شود.",
      openAction: "بازکردن اطلاعات آسیب‌پذیری",
      unavailableBadge: "متصل نیست",
    },
    systemHealth: {
      title: "سلامت سامانه",
      description: "نمایش‌های عملیاتی فقط‌خواندنی از آداپتور سمت‌سرور استفاده می‌کنند؛ مقدارها فقط وقتی نمایش داده می‌شوند که استقرار مورداعتماد پیکربندی شده و API دادهٔ معتبر برگرداند.",
      openAction: "بازکردن سلامت سامانه",
      unavailableBadge: "متصل نیست",
    },
    coordination: {
      title: "هماهنگی عامل‌ها",
      description: "نمای فقط‌خواندنی عامل، وظیفه، معیار و رویداد از آداپتور سمت‌سرور استفاده می‌کند و تا زمان پیکربندی استقرار مورداعتماد در دسترس نیست.",
      openAction: "بازکردن هماهنگی عامل‌ها",
      unavailableBadge: "متصل نیست",
    },
  },
};

type DestinationId = keyof Pick<OverviewMessages,
  "commandTheater" | "threatIntelligence" | "vulnerabilityIntelligence" | "systemHealth" | "coordination"
>;

const destinations: { id: DestinationId; href: string }[] = [
  { id: "commandTheater", href: "/command-theater" },
  { id: "threatIntelligence", href: "/threat-intelligence" },
  { id: "vulnerabilityIntelligence", href: "/vulnerability-intelligence" },
  { id: "systemHealth", href: "/system-health" },
  { id: "coordination", href: "/coordination" },
];

export function WorkspaceOverview({ demoMode }: WorkspaceOverviewProps) {
  const workspaceLocale = useCiccLocale();
  const locale = workspaceLocale?.locale ?? "en";
  const messages = overviewMessages[locale];
  const id = useId().replaceAll(":", "");

  return (
    <div className={styles.page} lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <header className={styles.hero}>
        <div className={styles.heroCopy}>
          <p className={styles.eyebrow}>{messages.eyebrow}</p>
          <h1 id={`${id}-title`}>{messages.title}</h1>
          <p className={styles.introduction}>{messages.introduction}</p>
        </div>
        <span className={styles.scopeBadge}>{messages.scopeLabel}</span>
      </header>

      <aside className={styles.integrationNotice} aria-labelledby={`${id}-integration-title`}>
        <span className={styles.noticeGlyph} aria-hidden="true">
          <svg viewBox="0 0 24 24" focusable="false">
            <path d="M12 3.5 21 20H3z" />
            <path d="M12 9v5m0 3h.01" />
          </svg>
        </span>
        <div>
          <h2 id={`${id}-integration-title`}>
            {demoMode ? messages.integrationTitleDemo : messages.integrationTitleUnavailable}
          </h2>
          <p>
            {demoMode ? messages.integrationDescriptionDemo : messages.integrationDescriptionUnavailable}
          </p>
        </div>
      </aside>

      <section className={styles.workflows} aria-labelledby={`${id}-workflows-title`}>
        <div className={styles.sectionHeading}>
          <div>
            <p className={styles.eyebrow}>{messages.workflowEyebrow}</p>
            <h2 id={`${id}-workflows-title`}>{messages.workflowTitle}</h2>
            <p>{messages.workflowDescription}</p>
          </div>
        </div>

        <div className={styles.moduleGrid}>
          {destinations.map(({ id: destinationId, href }) => {
            const destination = messages[destinationId];
            const titleId = `${id}-${destinationId}-title`;
            const descriptionId = `${id}-${destinationId}-description`;
            const statusId = `${id}-${destinationId}-status`;
            const demoIsVisible = destinationId === "commandTheater" && demoMode;
            return (
              <Link
                className={styles.moduleCard}
                href={href}
                key={destinationId}
                aria-labelledby={titleId}
                aria-describedby={`${descriptionId} ${statusId}`}
              >
                <div className={styles.cardTopline}>
                  <span className={styles.moduleGlyph} aria-hidden="true">
                    <ModuleGlyph id={destinationId} />
                  </span>
                  <span id={statusId} className={demoIsVisible ? styles.demoBadge : styles.providerBadge}>
                    {demoIsVisible ? messages.demoBadge : destination.unavailableBadge}
                  </span>
                </div>
                <h3 id={titleId}>{destination.title}</h3>
                <p id={descriptionId}>{destination.description}</p>
                <span className={styles.cardAction}>
                  {destination.openAction}
                  <span aria-hidden="true">↗</span>
                </span>
              </Link>
            );
          })}
        </div>
      </section>

      <div className={styles.dashboardSignals}>
        <section className={styles.signalPanel} aria-labelledby={`${id}-freshness-title`}>
          <h2 id={`${id}-freshness-title`}>{messages.sourceFreshnessTitle}</h2>
          <p className={styles.signalDescription}>
            {demoMode ? messages.sourceFreshnessDemoDescription : messages.sourceFreshnessDescription}
          </p>
        </section>

        <section className={styles.signalPanel} aria-labelledby={`${id}-events-title`}>
          <h2 id={`${id}-events-title`}>{messages.recentEventsTitle}</h2>
          <p className={styles.signalDescription}>
            {demoMode ? messages.recentEventsDemoDescription : messages.recentEventsDescription}
          </p>
          <nav className={styles.eventLinks} aria-label={messages.eventDestinationsLabel}>
            <Link href="/coordination">{messages.coordination.openAction}</Link>
            <Link href="/system-health">{messages.systemHealth.openAction}</Link>
          </nav>
        </section>
      </div>

      <aside className={styles.integrityNote} aria-labelledby={`${id}-integrity-title`}>
        <span className={styles.integrityMark} aria-hidden="true">i</span>
        <div>
          <h2 id={`${id}-integrity-title`}>{messages.dataIntegrityTitle}</h2>
          <p>{messages.dataIntegrityDescription}</p>
        </div>
      </aside>
    </div>
  );
}

function ModuleGlyph({ id }: { id: DestinationId }) {
  if (id === "commandTheater") {
    return <svg viewBox="0 0 24 24" focusable="false">
      <circle cx="6" cy="7" r="2" />
      <circle cx="18" cy="6" r="2" />
      <circle cx="12" cy="18" r="2" />
      <path d="m8 7 8-1M7 9l4 7m6-8-4 8" />
    </svg>;
  }
  if (id === "threatIntelligence") {
    return <svg viewBox="0 0 24 24" focusable="false">
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1" />
    </svg>;
  }
  if (id === "vulnerabilityIntelligence") {
    return <svg viewBox="0 0 24 24" focusable="false">
      <path d="M12 3 20 6v5c0 5-3.4 8.2-8 10-4.6-1.8-8-5-8-10V6z" />
      <path d="M12 8v5m0 3h.01" />
    </svg>;
  }
  if (id === "systemHealth") {
    return <svg viewBox="0 0 24 24" focusable="false">
      <path d="M3 12h4l2-6 4 12 2-6h6" />
      <circle cx="3" cy="12" r="1" />
      <circle cx="21" cy="12" r="1" />
    </svg>;
  }
  return <svg viewBox="0 0 24 24" focusable="false">
    <circle cx="12" cy="5" r="2" />
    <circle cx="6" cy="18" r="2" />
    <circle cx="18" cy="18" r="2" />
    <path d="m11 7-4 9m6-9 4 9M8 18h8" />
  </svg>;
}
