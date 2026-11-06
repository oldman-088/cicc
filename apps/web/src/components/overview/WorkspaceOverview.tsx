"use client";

import Link from "next/link";
import { useId } from "react";
import type { Locale } from "../application/localization";
import { useCiccLocale } from "../application/CiccApplication";
import { BetaReadinessPanel } from "./BetaReadinessPanel";
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
    integrationTitleUnavailable: "Check provider status below",
    integrationDescriptionUnavailable: "System Health and Coordination are checked on demand through their existing read-only server adapters. Their panels show only provider-reported status and request failures; a response from either provider is not a whole-platform health guarantee. Threat Intelligence, Vulnerability Intelligence, and the domain lifecycle surface remain unbound until host integration is verified.",
    workflowEyebrow: "WORKSPACE MODULES",
    workflowTitle: "Explore the workspace",
    workflowDescription: "Routes are navigable; each module states plainly whether its data integration is connected.",
    demoBadge: "Synthetic demo in development",
    dataIntegrityTitle: "Data integrity",
    dataIntegrityDescription: "A visible page is not evidence of live data. Unconfigured, unavailable, cached, and synthetic states remain distinct; no live counts or service health are inferred.",
    sourceFreshnessTitle: "Data sources and freshness",
    sourceFreshnessDescription: "The on-demand checks below show the provider timestamps, response-received times, and cache metadata actually returned. They do not aggregate a cross-domain freshness score; Threat Intelligence and Vulnerability Intelligence remain unbound and have no production records here.",
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
      description: "Provider-reported operational telemetry is checked on demand below; failures and missing configuration remain visible as such.",
      openAction: "Open System Health",
      unavailableBadge: "On-demand check",
    },
    coordination: {
      title: "Agent Coordination",
      description: "The provider-reported Coordination health is checked on demand below; no lifecycle or tenant health is inferred.",
      openAction: "Open Agent Coordination",
      unavailableBadge: "On-demand check",
    },
  },
  ar: {
    eyebrow: "CICC / مساحة العمل",
    title: "نظرة عامة على مساحة العمل",
    introduction: "نقطة بداية شفافة لوحدات الواجهة الموجودة في هذا الإصدار.",
    scopeLabel: "مساحة الواجهة الأمامية",
    integrationTitleDemo: "بيانات تطوير اصطناعية فقط",
    integrationDescriptionDemo: "يمكن لمسرح القيادة تحميل سجلات اصطناعية معزولة أثناء التطوير. وتُوسم بوضوح بأنها اصطناعية ولا تُعرض مطلقاً كمعلومات حية.",
    integrationTitleUnavailable: "تحقق من حالة المزوّد أدناه",
    integrationDescriptionUnavailable: "تُفحص سلامة النظام والتنسيق عند الطلب عبر محوّلاتهما الخادمية الحالية للقراءة فقط. تعرض اللوحات حالة المزوّد وأخطاء الطلب فقط؛ ولا تضمن استجابة أي منهما سلامة المنصة بأكملها. تظل استخبارات التهديدات والثغرات ودورة حياة المجالات غير مركّبة حتى التحقق من تكامل المضيف.",
    workflowEyebrow: "وحدات مساحة العمل",
    workflowTitle: "استكشف مساحة العمل",
    workflowDescription: "يمكن فتح المسارات، وتوضح كل وحدة صراحةً ما إذا كان تكامل بياناتها متصلاً.",
    demoBadge: "عرض اصطناعي في بيئة التطوير",
    dataIntegrityTitle: "سلامة البيانات",
    dataIntegrityDescription: "وجود صفحة لا يعني وجود بيانات حية. تبقى الحالات غير المهيأة وغير المتاحة والمخزنة مؤقتاً والاصطناعية متميزة؛ ولا تُستنتج أعداد حية أو سلامة خدمات.",
    sourceFreshnessTitle: "مصادر البيانات وحداثتها",
    sourceFreshnessDescription: "تعرض الفحوصات عند الطلب أدناه الطوابع الزمنية وأوقات استلام الاستجابة وبيانات التخزين المؤقت التي أعادها المزوّد فعلياً. ولا تستنتج درجة حداثة موحّدة للمجالات؛ كما تظل استخبارات التهديدات والثغرات غير مركّبة بلا سجلات إنتاجية هنا.",
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
      description: "تُفحص القياسات التشغيلية التي أبلغ عنها المزوّد عند الطلب أدناه؛ وتبقى الأخطاء وغياب الإعداد ظاهرين.",
      openAction: "فتح سلامة النظام",
      unavailableBadge: "فحص عند الطلب",
    },
    coordination: {
      title: "تنسيق الوكلاء",
      description: "تُفحص صحة التنسيق التي أبلغ عنها المزوّد عند الطلب أدناه؛ ولا تُستنتج صحة دورة الحياة أو المستأجر.",
      openAction: "فتح تنسيق الوكلاء",
      unavailableBadge: "فحص عند الطلب",
    },
  },
  fa: {
    eyebrow: "CICC / فضای کاری",
    title: "نمای کلی فضای کاری",
    introduction: "نقطهٔ شروعی شفاف برای ماژول‌های رابط کاربری موجود در این ساخت.",
    scopeLabel: "فضای رابط کاربری",
    integrationTitleDemo: "فقط نمونهٔ ساختگی توسعه",
    integrationDescriptionDemo: "تالار فرماندهی می‌تواند هنگام توسعه رکوردهای ساختگی جداگانه بارگیری کند. این رکوردها آشکارا ساختگی علامت‌گذاری می‌شوند و هرگز اطلاعات زنده معرفی نمی‌شوند.",
    integrationTitleUnavailable: "وضعیت منبع را در پایین بررسی کنید",
    integrationDescriptionUnavailable: "سلامت سامانه و هماهنگی هنگام درخواست از طریق آداپتورهای فعلی سمت‌سرور و فقط‌خواندنی بررسی می‌شوند. پنل‌ها فقط وضعیت گزارش‌شده و خطای درخواست را نشان می‌دهند؛ پاسخ هرکدام تضمین سلامت کل پلتفرم نیست. اطلاعات تهدید، آسیب‌پذیری و چرخهٔ عمر دامنه تا زمان تأیید یکپارچه‌سازی میزبان متصل نیستند.",
    workflowEyebrow: "ماژول‌های فضای کاری",
    workflowTitle: "کاوش در فضای کاری",
    workflowDescription: "مسیرها قابل پیمایش‌اند و هر ماژول روشن می‌گوید که آیا اتصال داده دارد یا نه.",
    demoBadge: "نمای ساختگی در محیط توسعه",
    dataIntegrityTitle: "درستی داده‌ها",
    dataIntegrityDescription: "وجود صفحه به‌معنای دادهٔ زنده نیست. وضعیت‌های پیکربندی‌نشده، ناموجود، کش‌شده و ساختگی متمایزند؛ تعداد زنده یا سلامت سرویس حدس زده نمی‌شود.",
    sourceFreshnessTitle: "منبع داده و تازگی",
    sourceFreshnessDescription: "بررسی‌های هنگام درخواست در پایین، مُهرهای زمانی، زمان دریافت پاسخ و فرادادهٔ کشِ بازگشتی از ارائه‌دهنده را نشان می‌دهند. امتیاز تازگی بین‌دامنه‌ای استنباط نمی‌شود؛ اطلاعات تهدید و آسیب‌پذیری متصل نیستند و اینجا رکورد تولیدی ندارند.",
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
      description: "دادهٔ عملیاتی گزارش‌شده از ارائه‌دهنده در پایین و هنگام درخواست بررسی می‌شود؛ خطاها و نبود پیکربندی آشکار می‌مانند.",
      openAction: "بازکردن سلامت سامانه",
      unavailableBadge: "بررسی هنگام درخواست",
    },
    coordination: {
      title: "هماهنگی عامل‌ها",
      description: "سلامت هماهنگی طبق گزارش ارائه‌دهنده در پایین بررسی می‌شود؛ سلامت چرخهٔ عمر یا مستأجر استنباط نمی‌شود.",
      openAction: "بازکردن هماهنگی عامل‌ها",
      unavailableBadge: "بررسی هنگام درخواست",
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

      <BetaReadinessPanel />

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
