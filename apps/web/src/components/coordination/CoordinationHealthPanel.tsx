"use client";

import type { Locale } from "../application/localization";
import {
  integrationEndpoints,
  parseCoordinationHealth,
  parseProviderTimestamp,
  type CoordinationHealth,
} from "../../lib/integration-api";
import { ResourcePanel } from "../integrations/ResourcePanel";
import { useIntegrationResource } from "../integrations/useIntegrationResource";
import styles from "./CoordinationWorkspace.module.css";

const copy = {
  en: {
    title: "Coordination health",
    overall: "Overall",
    checkedAt: "Checked at",
    onDemandNote: "Checked on demand when this page loads or is refreshed — this is not continuous monitoring.",
    reasons: "Reasons reported by the provider",
    lastOperations: "Last recorded operations",
    lastWebhook: "Last webhook received",
    lastSyncSuccess: "Last successful GitHub sync",
    lastSyncAttempt: "Last GitHub sync attempt",
    lastTaskEvent: "Last task event",
    noValue: "Not provided",
    noTimestamp: "Not provided",
  },
  ar: {
    title: "صحة التنسيق",
    overall: "الإجمالي",
    checkedAt: "وقت الفحص",
    onDemandNote: "يُفحص عند الطلب عند تحميل هذه الصفحة أو تحديثها — وليس مراقبة مستمرة.",
    reasons: "الأسباب التي أبلغ عنها المزوّد",
    lastOperations: "آخر العمليات المسجّلة",
    lastWebhook: "آخر ويب هوك مستلم",
    lastSyncSuccess: "آخر مزامنة ناجحة مع GitHub",
    lastSyncAttempt: "آخر محاولة مزامنة مع GitHub",
    lastTaskEvent: "آخر حدث مهمة",
    noValue: "غير متوفر",
    noTimestamp: "غير متوفر",
  },
  fa: {
    title: "سلامت هماهنگی",
    overall: "کلی",
    checkedAt: "زمان بررسی",
    onDemandNote: "هنگام بارگذاری یا بازخوانی این صفحه و بر اساس درخواست بررسی می‌شود — این پایش پیوسته نیست.",
    reasons: "دلایل گزارش‌شده از سوی منبع",
    lastOperations: "آخرین عملیات ثبت‌شده",
    lastWebhook: "آخرین وب‌هوک دریافتی",
    lastSyncSuccess: "آخرین همگام‌سازی موفق GitHub",
    lastSyncAttempt: "آخرین تلاش همگام‌سازی GitHub",
    lastTaskEvent: "آخرین رویداد وظیفه",
    noValue: "ارائه نشده است",
    noTimestamp: "ارائه نشده است",
  },
} as const;

type Messages = {
  title: string; overall: string; checkedAt: string; onDemandNote: string; reasons: string;
  lastOperations: string; lastWebhook: string; lastSyncSuccess: string; lastSyncAttempt: string;
  lastTaskEvent: string; noValue: string; noTimestamp: string;
};

function formatTimestamp(value: string | null, locale: Locale, fallback: string): string {
  const date = parseProviderTimestamp(value);
  if (!date) return fallback;
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(date);
}

function formatNumber(value: number, locale: Locale): string {
  return new Intl.NumberFormat(locale).format(value);
}

function HealthContent({ data, locale, messages }: { data: CoordinationHealth; locale: Locale; messages: Messages }) {
  const degraded = data.overall !== "healthy";
  return (
    <div>
      <p>
        <strong>{messages.overall}:</strong>{" "}
        <span className={degraded ? `${styles.statusTag} ${styles.warningTag}` : styles.statusTag}>
          <bdi dir="ltr">{data.overall}</bdi>
        </span>
        {data.at && <> · {messages.checkedAt}: {formatTimestamp(data.at, locale, messages.noTimestamp)}</>}
      </p>
      <ul className={styles.agentList}>
        {data.components.map((component) => (
          <li key={component.key} className={styles.recordCard}>
            <div className={styles.cardHeading}>
              <h3><bdi dir="ltr">{component.key}</bdi></h3>
              <span className={component.status !== "healthy" ? `${styles.statusTag} ${styles.warningTag}` : styles.statusTag}>
                <bdi dir="ltr">{component.status}</bdi>
              </span>
            </div>
            {component.detail && <p dir="auto">{component.detail}</p>}
            {component.reasons.length > 0 && (
              <ul>{component.reasons.map((reason) => <li key={reason}><bdi dir="auto">{reason}</bdi></li>)}</ul>
            )}
          </li>
        ))}
      </ul>
      {data.last_operations && (
        <>
          <h3>{messages.lastOperations}</h3>
          <dl className={styles.smallMeta}>
            <div><dt>{messages.lastWebhook}</dt><dd>{formatTimestamp(data.last_operations.last_webhook_received, locale, messages.noValue)}</dd></div>
            <div><dt>{messages.lastSyncSuccess}</dt><dd>{formatTimestamp(data.last_operations.last_github_sync_success, locale, messages.noValue)}</dd></div>
            <div><dt>{messages.lastSyncAttempt}</dt><dd>{formatTimestamp(data.last_operations.last_github_sync_attempt, locale, messages.noValue)}</dd></div>
            <div><dt>{messages.lastTaskEvent}</dt><dd>{formatTimestamp(data.last_operations.last_task_event, locale, messages.noValue)}</dd></div>
          </dl>
          {data.last_operations.note && <p className={styles.scopeNote}><bdi dir="auto">{data.last_operations.note}</bdi></p>}
        </>
      )}
      {data.reasons.length > 0 && (
        <>
          <h3>{messages.reasons}</h3>
          <ul>{data.reasons.map((reason) => <li key={reason}><bdi dir="auto">{reason}</bdi></li>)}</ul>
        </>
      )}
    </div>
  );
}

/**
 * On-demand coordination health (Agent 1 M28/M29). One request per page
 * load or explicit refresh — never polling, never described as continuous
 * monitoring. Backward compatible with M28 payloads (no last_operations).
 */
export function CoordinationHealthPanel({ locale }: { locale: Locale }) {
  const text = copy[locale];
  const health = useIntegrationResource(integrationEndpoints.coordinationHealth, parseCoordinationHealth);
  return (
    <div>
      <ResourcePanel title={text.title} state={health.state} onRefresh={health.refresh}>
        {(data) => <HealthContent data={data} locale={locale} messages={text} />}
      </ResourcePanel>
      <p className={styles.scopeNote}>{text.onDemandNote}</p>
    </div>
  );
}

export { formatNumber as coordinationFormatNumber };
