"use client";

import { useId } from "react";
import type { Locale } from "../application/localization";
import { useCiccLocale } from "../application/CiccApplication";
import {
  integrationEndpoints,
  parseOpsAlerts,
  parseOpsOverview,
  parseOpsWorkers,
  type OpsActivityEvent,
  type OpsAlert,
  type OpsComponent,
  type OpsOverview,
  type OpsWorkers,
} from "../../lib/integration-api";
import { ResourcePanel } from "../integrations/ResourcePanel";
import { CoordinationHealthPanel } from "../coordination/CoordinationHealthPanel";
import { useIntegrationResource } from "../integrations/useIntegrationResource";
import styles from "./SystemHealthWorkspace.module.css";

type Messages = {
  eyebrow: string;
  title: string;
  intro: string;
  readOnly: string;
  scopeWarning: string;
  overview: string;
  overallStatus: string;
  services: string;
  modules: string;
  metrics: string;
  activity: string;
  alerts: string;
  workers: string;
  source: string;
  generatedAt: string;
  cacheState: string;
  cached: string;
  notCached: string;
  cacheUnknown: string;
  cacheAge: string;
  sourceUnknown: string;
  serviceEmpty: string;
  moduleEmpty: string;
  activityEmpty: string;
  alertEmpty: string;
  workerEmpty: string;
  metricEntities: string;
  metricVulnerabilities: string;
  metricCampaigns: string;
  metricUpdates: string;
  metricSync: string;
  metricsUnverified: string;
  diagnostics: string;
  diagDegraded: string;
  diagCached: string;
  diagUnverifiedSource: string;
  diagNone: string;
  diagStalled: string;
  detail: string;
  lastCheck: string;
  severity: string;
  occurrences: string;
  component: string;
  stalled: string;
  reportedNotStalled: string;
  tasks24h: string;
  failed24h: string;
  stallThreshold: string;
  noTimestamp: string;
  level: string;
  owner: string;
  noOwner: string;
};

const copy: Record<Locale, Messages> = {
  en: {
    eyebrow: "CICC / OPERATIONS",
    title: "System Health",
    intro: "Read-only operational telemetry returned by the configured CICC operations provider.",
    readOnly: "READ ONLY",
    scopeWarning: "Trusted single-tenant scope: the current provider has no tenant isolation, and this frontend does not authenticate users. Do not expose this deployment to untrusted users or multiple tenants.",
    overview: "Operational overview",
    overallStatus: "Provider-reported overall status",
    services: "Services",
    modules: "Modules",
    metrics: "Operational metrics",
    activity: "Recent activity returned by the overview API",
    alerts: "Active operational alerts",
    workers: "Worker liveness",
    source: "Provider data source",
    generatedAt: "Overview generated at",
    cacheState: "Cache state reported by API",
    cached: "Cached response",
    notCached: "API marked this response as not cached",
    cacheUnknown: "Cache state not provided",
    cacheAge: "Cache age",
    sourceUnknown: "Metric values withheld: this frontend has not verified the returned data-source label.",
    serviceEmpty: "The provider returned no service records.",
    moduleEmpty: "The provider returned no module records.",
    activityEmpty: "The provider returned no activity records.",
    alertEmpty: "The API returned no active alert records. This is not, by itself, a guarantee that every service is healthy.",
    workerEmpty: "The provider returned no worker records.",
    metricEntities: "Entities",
    metricVulnerabilities: "Vulnerabilities",
    metricCampaigns: "Campaigns",
    metricUpdates: "Updates in 24 hours",
    metricSync: "Last successful sync",
    metricsUnverified: "Metrics are hidden because the provider did not return the currently documented source label (live-ops-database).",
    diagnostics: "Diagnostics from this on-demand check",
    diagDegraded: "Reported not healthy by the provider",
    diagCached: "This response is cached; values may be stale. Use Refresh for a new on-demand check.",
    diagUnverifiedSource: "Metrics are hidden because this data source is not the verified live operations database.",
    diagNone: "No degraded items were derived from this response. This is not a guarantee that all services are healthy.",
    diagStalled: "Stalled per provider (age exceeds the stall threshold)",
    detail: "Provider detail",
    lastCheck: "Last check reported by provider",
    severity: "Severity",
    occurrences: "Occurrences",
    component: "Component",
    stalled: "Provider reports stalled",
    reportedNotStalled: "Provider reports not stalled",
    tasks24h: "Tasks in 24 hours",
    failed24h: "Failed in 24 hours",
    stallThreshold: "Stall threshold",
    noTimestamp: "Not provided",
    level: "Level",
    owner: "Owner / acknowledged by",
    noOwner: "No owner reported",
  },
  ar: {
    eyebrow: "CICC / العمليات",
    title: "سلامة النظام",
    intro: "قياسات تشغيلية للقراءة فقط أعادها مزوّد عمليات CICC المضبوط.",
    readOnly: "للقراءة فقط",
    scopeWarning: "نطاق موثوق لمستأجر واحد: لا يوفّر المزوّد الحالي عزل المستأجرين، ولا تصادق هذه الواجهة على المستخدمين. لا تعرض هذا النشر لمستخدمين غير موثوقين أو لعدة مستأجرين.",
    overview: "نظرة تشغيلية عامة",
    overallStatus: "الحالة العامة كما أبلغ عنها المزوّد",
    services: "الخدمات",
    modules: "الوحدات",
    metrics: "المقاييس التشغيلية",
    activity: "النشاط الأخير الذي أعاده API النظرة العامة",
    alerts: "التنبيهات التشغيلية النشطة",
    workers: "حيوية العمال",
    source: "مصدر بيانات المزوّد",
    generatedAt: "وقت إنشاء النظرة العامة",
    cacheState: "حالة التخزين المؤقت كما أبلغ عنها API",
    cached: "استجابة مخزنة مؤقتاً",
    notCached: "أفاد API بأن هذه الاستجابة غير مخزنة مؤقتاً",
    cacheUnknown: "لم تُقدّم حالة التخزين المؤقت",
    cacheAge: "عمر التخزين المؤقت",
    sourceUnknown: "حُجبت قيم المقاييس: لم تتحقق الواجهة من تسمية مصدر البيانات المُعادة.",
    serviceEmpty: "لم يُرجع المزوّد سجلات للخدمات.",
    moduleEmpty: "لم يُرجع المزوّد سجلات للوحدات.",
    activityEmpty: "لم يُرجع المزوّد سجلات للنشاط.",
    alertEmpty: "لم يُرجع API سجلات لتنبيهات نشطة. وهذا وحده لا يضمن سلامة جميع الخدمات.",
    workerEmpty: "لم يُرجع المزوّد سجلات للعمال.",
    metricEntities: "الكيانات",
    metricVulnerabilities: "الثغرات",
    metricCampaigns: "الحملات",
    metricUpdates: "التحديثات خلال 24 ساعة",
    metricSync: "آخر مزامنة ناجحة",
    metricsUnverified: "أُخفيت المقاييس لأن المزوّد لم يُرجع تسمية المصدر الموثّقة حالياً (live-ops-database).",
    diagnostics: "التشخيص من هذا الفحص عند الطلب",
    diagDegraded: "أبلغ المزوّد أنه غير سليم",
    diagCached: "هذه الاستجابة مخزّنة مؤقتاً؛ قد تكون القيم قديمة. استخدم التحديث لفحص جديد عند الطلب.",
    diagUnverifiedSource: "المقاييس مخفية لأن مصدر البيانات هذا ليس قاعدة بيانات العمليات الحية الموثّقة.",
    diagNone: "لم تُستنتج عناصر متدهورة من هذه الاستجابة. هذا ليس ضماناً بأن كل الخدمات سليمة.",
    diagStalled: "متوقف بحسب المزوّد (العمر يتجاوز عتبة التوقف)",
    detail: "تفصيل المزوّد",
    lastCheck: "آخر فحص بحسب المزوّد",
    severity: "الشدة",
    occurrences: "مرات الحدوث",
    component: "المكوّن",
    stalled: "أفاد المزوّد بأنه متوقف",
    reportedNotStalled: "أفاد المزوّد بأنه غير متوقف",
    tasks24h: "المهام خلال 24 ساعة",
    failed24h: "المهام الفاشلة خلال 24 ساعة",
    stallThreshold: "حد التوقف",
    noTimestamp: "غير متوفر",
    level: "المستوى",
    owner: "المالك / أقرّ بالاستلام",
    noOwner: "لم يُذكر مالك",
  },
  fa: {
    eyebrow: "CICC / عملیات",
    title: "سلامت سامانه",
    intro: "دادهٔ عملیاتی فقط‌خواندنی که منبع عملیات پیکربندی‌شدهٔ CICC برگردانده است.",
    readOnly: "فقط‌خواندنی",
    scopeWarning: "محدودهٔ استقرار مورداعتماد و تک‌مستاجری: منبع فعلی جداسازی مستأجر ندارد و این رابط کاربران را احراز هویت نمی‌کند. این استقرار را در معرض کاربران نامطمئن یا چند مستأجر قرار ندهید.",
    overview: "نمای کلی عملیات",
    overallStatus: "وضعیت کلی گزارش‌شده از منبع",
    services: "سرویس‌ها",
    modules: "ماژول‌ها",
    metrics: "معیارهای عملیاتی",
    activity: "فعالیت اخیر بازگشتی از API نمای کلی",
    alerts: "هشدارهای عملیاتی فعال",
    workers: "زنده‌بودن workerها",
    source: "منبع دادهٔ ارائه‌دهنده",
    generatedAt: "زمان تولید نمای کلی",
    cacheState: "وضعیت کش گزارش‌شده از API",
    cached: "پاسخ از کش",
    notCached: "API این پاسخ را کش‌نشده علامت زده است",
    cacheUnknown: "وضعیت کش ارائه نشده است",
    cacheAge: "سن کش",
    sourceUnknown: "مقادیر معیار پنهان شده‌اند: این رابط برچسب منبع دادهٔ بازگشتی را تأیید نکرده است.",
    serviceEmpty: "منبع هیچ رکورد سرویسی برنگرداند.",
    moduleEmpty: "منبع هیچ رکورد ماژولی برنگرداند.",
    activityEmpty: "منبع هیچ رکورد فعالیتی برنگرداند.",
    alertEmpty: "API هیچ هشدار فعالی برنگرداند. این موضوع به‌تنهایی تضمین نمی‌کند که همهٔ سرویس‌ها سالم‌اند.",
    workerEmpty: "منبع هیچ رکورد worker برنگرداند.",
    metricEntities: "موجودیت‌ها",
    metricVulnerabilities: "آسیب‌پذیری‌ها",
    metricCampaigns: "کارزارها",
    metricUpdates: "به‌روزرسانی در ۲۴ ساعت",
    metricSync: "آخرین همگام‌سازی موفق",
    metricsUnverified: "معیارها پنهان‌اند، چون منبع برچسب مستند فعلی (live-ops-database) را برنگرداند.",
    diagnostics: "تشخیص از این بررسی بر اساس درخواست",
    diagDegraded: "منبع آن را ناسالم گزارش کرده است",
    diagCached: "این پاسخ کش‌شده است؛ مقادیر ممکن است قدیمی باشند. برای بررسی تازه بر اساس درخواست از بازخوانی استفاده کنید.",
    diagUnverifiedSource: "معیارها پنهان‌اند چون این منبع داده پایگاه دادهٔ زندهٔ عملیاتِ راستی‌آزمایی‌شده نیست.",
    diagNone: "از این پاسخ مورد تخریب‌شده‌ای استخراج نشد. این تضمین نمی‌کند همهٔ سرویس‌ها سالم‌اند.",
    diagStalled: "طبق منبع متوقف است (سن از آستانهٔ توقف بیشتر است)",
    detail: "جزئیات ارائه‌دهنده",
    lastCheck: "آخرین بررسی گزارش‌شده از منبع",
    severity: "شدت",
    occurrences: "دفعات رخداد",
    component: "مؤلفه",
    stalled: "منبع توقف را گزارش می‌کند",
    reportedNotStalled: "منبع توقف را گزارش نمی‌کند",
    tasks24h: "وظایف در ۲۴ ساعت",
    failed24h: "وظایف ناموفق در ۲۴ ساعت",
    stallThreshold: "آستانهٔ توقف",
    noTimestamp: "ارائه نشده است",
    level: "سطح",
    owner: "مالک / تأییدکننده",
    noOwner: "مالک گزارش نشده است",
  },
};

function formatNumber(value: number, locale: Locale): string {
  return new Intl.NumberFormat(locale).format(value);
}

function formatTimestamp(value: string | null, locale: Locale, fallback: string): string {
  if (!value) return fallback;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function statusTone(status: string): string {
  const value = status.toLowerCase();
  if (["ok", "healthy", "online", "connected"].includes(value)) return styles.toneSuccess;
  if (["degraded", "warning", "stale", "maintenance"].includes(value)) return styles.toneWarning;
  if (["down", "error", "failed", "unavailable"].includes(value)) return styles.toneDanger;
  return styles.toneNeutral;
}

function ComponentList({
  title,
  items,
  emptyMessage,
  locale,
  messages,
}: {
  title: string;
  items: OpsComponent[];
  emptyMessage: string;
  locale: Locale;
  messages: Messages;
}) {
  return (
    <section className={styles.subsection} aria-label={title}>
      <h3>{title}</h3>
      {items.length === 0 ? <p className={styles.emptyInline}>{emptyMessage}</p> : (
        <ul className={styles.componentList}>
          {items.map((item) => (
            <li className={styles.componentCard} key={`${item.kind}:${item.key}`}>
              <div className={styles.cardHeading}>
                <div>
                  <h4><bdi dir="auto">{item.name}</bdi></h4>
                  <p className={styles.keyLine}><bdi dir="ltr">{item.kind} · {item.key}</bdi></p>
                </div>
                <span className={`${styles.statusTag} ${statusTone(item.status)}`}><bdi dir="auto">{item.status}</bdi></span>
              </div>
              <p className={styles.detail} dir="auto"><span>{messages.detail}: </span>{item.detail}</p>
              {item.last_check_at && (
                <p className={styles.timestamp}>
                  {messages.lastCheck}: {formatTimestamp(item.last_check_at, locale, messages.noTimestamp)}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function OverviewContent({ data, locale, messages }: { data: OpsOverview; locale: Locale; messages: Messages }) {
  const id = useId().replaceAll(":", "");
  const verifiedMetricSource = data.data_source === "live-ops-database";
  const metricValues = [
    [messages.metricEntities, data.metrics.entities],
    [messages.metricVulnerabilities, data.metrics.vulnerabilities],
    [messages.metricCampaigns, data.metrics.campaigns],
    [messages.metricUpdates, data.metrics.recent_updates_24h],
  ] as const;
  const cacheText = data.cached === true
    ? `${messages.cached}${data.cache_age_s === null ? "" : ` · ${messages.cacheAge}: ${formatNumber(data.cache_age_s, locale)}s`}`
    : data.cached === false ? messages.notCached : messages.cacheUnknown;

  return (
    <div className={styles.overviewContent}>
      <div className={styles.overviewMeta}>
        <div className={styles.overallBlock}>
          <span className={styles.metaLabel}>{messages.overallStatus}</span>
          <span className={`${styles.overallStatus} ${statusTone(data.overall_status)}`}><bdi dir="auto">{data.overall_status}</bdi></span>
        </div>
        <dl className={styles.metaList}>
          <div><dt>{messages.source}</dt><dd><code><bdi dir="ltr">{data.data_source}</bdi></code></dd></div>
          <div><dt>{messages.generatedAt}</dt><dd>{formatTimestamp(data.generated_at, locale, messages.noTimestamp)}</dd></div>
          <div><dt>{messages.cacheState}</dt><dd>{cacheText}</dd></div>
        </dl>
      </div>

      <div className={styles.componentColumns}>
        <ComponentList title={messages.services} items={data.services} emptyMessage={messages.serviceEmpty} locale={locale} messages={messages} />
        <ComponentList title={messages.modules} items={data.modules} emptyMessage={messages.moduleEmpty} locale={locale} messages={messages} />
      </div>

      <section className={styles.subsection} aria-labelledby={`${id}-diagnostics`}>
        <h3 id={`${id}-diagnostics`}>{messages.diagnostics}</h3>
        {(() => {
          const degraded = [...data.services, ...data.modules].filter((c) => statusTone(c.status) !== styles.toneSuccess);
          const items: string[] = [];
          if (data.cached === true) items.push(messages.diagCached);
          if (!verifiedMetricSource) items.push(messages.diagUnverifiedSource);
          return degraded.length === 0 && items.length === 0 ? <p className={styles.emptyInline}>{messages.diagNone}</p> : (
            <ul>
              {items.map((item) => <li key={item}>{item}</li>)}
              {degraded.map((c) => (
                <li key={`${c.kind}:${c.key}`}>
                  <bdi dir="auto">{c.name}</bdi> — {messages.diagDegraded}: <bdi dir="auto">{c.status}</bdi>
                  {c.detail && <> · <bdi dir="auto">{c.detail}</bdi></>}
                </li>
              ))}
            </ul>
          );
        })()}
      </section>

      <section className={styles.subsection} aria-labelledby={`${id}-metrics`}>
        <h3 id={`${id}-metrics`}>{messages.metrics}</h3>
        {verifiedMetricSource ? (
          <>
            <dl className={styles.metricGrid}>
              {metricValues.map(([label, value]) => (
                <div className={styles.metricCard} key={label}>
                  <dt>{label}</dt><dd>{formatNumber(value, locale)}</dd>
                </div>
              ))}
              <div className={styles.metricCard}>
                <dt>{messages.metricSync}</dt>
                <dd>{formatTimestamp(data.metrics.last_successful_sync, locale, messages.noTimestamp)}</dd>
              </div>
            </dl>
          </>
        ) : <p className={styles.unverified}>{messages.metricsUnverified}</p>}
      </section>

      <ActivityList events={data.activity} locale={locale} messages={messages} />
    </div>
  );
}

function ActivityList({ events, locale, messages }: { events: OpsActivityEvent[]; locale: Locale; messages: Messages }) {
  const id = useId().replaceAll(":", "");
  return (
    <section className={styles.subsection} aria-labelledby={`${id}-activity`}>
      <h3 id={`${id}-activity`}>{messages.activity}</h3>
      {events.length === 0 ? <p className={styles.emptyInline}>{messages.activityEmpty}</p> : (
        <ol className={styles.activityList}>
          {events.map((event) => (
            <li key={event.id}>
              <div className={styles.activityTopline}>
                <span className={styles.activitySource}><bdi dir="auto">{event.source}</bdi></span>
                <span className={styles.statusTag}>{messages.level}: <bdi dir="auto">{event.level}</bdi></span>
              </div>
              <p dir="auto">{event.message}</p>
              {event.ts && <time dateTime={event.ts}>{formatTimestamp(event.ts, locale, messages.noTimestamp)}</time>}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function AlertsContent({ alerts, locale, messages }: { alerts: OpsAlert[]; locale: Locale; messages: Messages }) {
  return (
    <ul className={styles.alertList}>
      {alerts.map((alert) => (
        <li key={alert.id} className={styles.alertCard}>
          <div className={styles.cardHeading}>
            <h3><bdi dir="auto">{alert.rule}</bdi></h3>
            <span className={`${styles.statusTag} ${statusTone(alert.severity)}`}>{messages.severity}: <bdi dir="auto">{alert.severity}</bdi></span>
          </div>
          <p className={styles.alertMessage} dir="auto">{alert.message}</p>
          <dl className={styles.smallMeta}>
            <div><dt>{messages.component}</dt><dd><bdi dir="ltr">{alert.component_key ?? "—"}</bdi></dd></div>
            <div><dt>{messages.occurrences}</dt><dd>{formatNumber(alert.occurrences, locale)}</dd></div>
            <div><dt>{messages.lastCheck}</dt><dd>{formatTimestamp(alert.last_seen, locale, messages.noTimestamp)}</dd></div>
            <div><dt>{messages.owner}</dt><dd><bdi dir="auto">{alert.owner ?? alert.acked_by ?? messages.noOwner}</bdi></dd></div>
          </dl>
        </li>
      ))}
    </ul>
  );
}

function WorkersContent({ data, locale, messages }: { data: OpsWorkers; locale: Locale; messages: Messages }) {
  return (
    <div>
      <p className={styles.threshold}>
        {messages.stallThreshold}: {formatNumber(data.stall_threshold_s, locale)}s
      </p>
      <ul className={styles.workerList}>
        {data.workers.map((worker) => (
          <li key={worker.worker} className={styles.workerCard}>
            <div className={styles.cardHeading}>
              <h3><bdi dir="ltr">{worker.worker}</bdi></h3>
              <span className={`${styles.statusTag} ${worker.stalled ? styles.toneWarning : styles.toneNeutral}`}>
                {worker.stalled ? messages.stalled : messages.reportedNotStalled}
              </span>
            </div>
            {worker.details && <p className={styles.detail} dir="auto">{worker.details}</p>}
            {worker.stalled && <p className={styles.detail}>{messages.diagStalled}{worker.age_s !== null ? ` · ${formatNumber(worker.age_s, locale)}s` : ""}</p>}
            <dl className={styles.smallMeta}>
              <div><dt>{messages.tasks24h}</dt><dd>{formatNumber(worker.tasks_24h, locale)}</dd></div>
              <div><dt>{messages.failed24h}</dt><dd>{formatNumber(worker.failed_24h, locale)}</dd></div>
              <div><dt>{messages.lastCheck}</dt><dd>{formatTimestamp(worker.last_seen, locale, messages.noTimestamp)}</dd></div>
            </dl>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function SystemHealthWorkspace() {
  const locale = useCiccLocale()?.locale ?? "en";
  const text = copy[locale];
  const id = useId().replaceAll(":", "");
  const overview = useIntegrationResource(integrationEndpoints.opsOverview, parseOpsOverview);
  const alerts = useIntegrationResource(integrationEndpoints.opsAlerts, parseOpsAlerts);
  const workers = useIntegrationResource(integrationEndpoints.opsWorkers, parseOpsWorkers);

  return (
    <div className={styles.page} lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>{text.eyebrow}</p>
          <h1>{text.title}</h1>
          <p className={styles.intro}>{text.intro}</p>
        </div>
        <span className={styles.readOnly}>{text.readOnly}</span>
      </header>

      <aside className={styles.scopeWarning} aria-labelledby={`${id}-scope`}>
        <span className={styles.warningGlyph} aria-hidden="true">!</span>
        <p id={`${id}-scope`}>{text.scopeWarning}</p>
      </aside>

      <div className={styles.dashboardGrid}>
        <div className={styles.overviewPanel}>
          <ResourcePanel
            title={text.overview}
            state={overview.state}
            onRefresh={overview.refresh}
          >
            {(data) => <OverviewContent data={data} locale={locale} messages={text} />}
          </ResourcePanel>
        </div>

        <ResourcePanel
          title={text.alerts}
          state={alerts.state}
          onRefresh={alerts.refresh}
          isEmpty={(data) => data.alerts.length === 0}
          emptyMessage={text.alertEmpty}
        >
          {(data) => <AlertsContent alerts={data.alerts} locale={locale} messages={text} />}
        </ResourcePanel>

        <CoordinationHealthPanel locale={locale} />

        <ResourcePanel
          title={text.workers}
          state={workers.state}
          onRefresh={workers.refresh}
          isEmpty={(data) => data.workers.length === 0}
          emptyMessage={text.workerEmpty}
        >
          {(data) => <WorkersContent data={data} locale={locale} messages={text} />}
        </ResourcePanel>
      </div>
    </div>
  );
}
