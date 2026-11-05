"use client";

import { useId, type ReactNode } from "react";
import type { Locale } from "../application/localization";
import { useCiccLocale } from "../application/CiccApplication";
import type { IntegrationFailureKind } from "../../lib/integration-api";
import type { ResourceState } from "./useIntegrationResource";
import styles from "./ResourcePanel.module.css";

type CommonMessages = {
  refresh: string;
  loading: string;
  refreshing: string;
  stale: string;
  lastSuccess: string;
  empty: string;
  retrying: (seconds: number, attempt: number, max: number) => string;
  retryGuidance: string;
  errors: Record<IntegrationFailureKind, string>;
};

const messages: Record<Locale, CommonMessages> = {
  en: {
    refresh: "Refresh",
    loading: "Requesting provider data…",
    refreshing: "Refreshing; showing the last successful response while this request is pending.",
    stale: "Refresh failed; the data below is the last successful response, not a current provider check.",
    lastSuccess: "Last successful response received by this browser",
    empty: "The provider returned no records for this section.",
    retrying: (seconds, attempt, max) => `Retrying automatically in ${seconds}s (attempt ${attempt} of ${max}). You can also refresh manually.`,
    retryGuidance: "If this persists, wait and use Refresh. Do not repeatedly reload the page.",
    errors: {
      not_configured: "The server-side provider is not configured in this deployment.",
      unauthorized: "The provider rejected the server-side read credential. Check its deployment configuration.",
      forbidden: "The provider did not authorize this read request.",
      rate_limited: "The provider rate-limited this request. Wait briefly before retrying.",
      invalid_request: "The provider rejected the request parameters.",
      conflict: "The provider reports that this request conflicts with its current state.",
      expired: "The requested provider resource has expired.",
      payload_too_large: "The provider rejected this request because a size limit was exceeded.",
      invalid_response: "The provider response did not match the documented data shape.",
      not_found: "The requested provider resource was not found.",
      unavailable: "The provider could not be reached or returned an upstream error.",
      other: "The provider request failed.",
    },
  },
  ar: {
    refresh: "تحديث",
    loading: "جارٍ طلب بيانات المزوّد…",
    refreshing: "يجري التحديث؛ تُعرض آخر استجابة ناجحة إلى حين اكتمال الطلب.",
    stale: "فشل التحديث؛ البيانات أدناه هي آخر استجابة ناجحة وليست فحصاً حالياً للمزوّد.",
    lastSuccess: "وقت استلام هذا المتصفح لآخر استجابة ناجحة",
    empty: "لم يُرجع المزوّد سجلات لهذا القسم.",
    retrying: (seconds, attempt, max) => `ستتم إعادة المحاولة تلقائياً بعد ${seconds} ثانية (المحاولة ${attempt} من ${max}). يمكنك أيضاً التحديث يدوياً.`,
    retryGuidance: "إذا استمر ذلك، انتظر واستخدم التحديث. لا تُعد تحميل الصفحة مراراً.",
    errors: {
      not_configured: "لم يُضبط المزوّد من جهة الخادم في هذا النشر.",
      unauthorized: "رفض المزوّد بيانات القراءة الخادمية. تحقّق من إعدادات النشر.",
      forbidden: "لم يأذن المزوّد بطلب القراءة هذا.",
      rate_limited: "فرض المزوّد حدّاً على الطلب. انتظر قليلاً قبل إعادة المحاولة.",
      invalid_request: "رفض المزوّد معاملات الطلب.",
      conflict: "أفاد المزوّد بأن هذا الطلب يتعارض مع حالته الحالية.",
      expired: "انتهت صلاحية المورد المطلوب لدى المزوّد.",
      payload_too_large: "رفض المزوّد الطلب لتجاوز حد الحجم.",
      invalid_response: "لا تطابق استجابة المزوّد شكل البيانات الموثّق.",
      not_found: "لم يُعثر على المورد المطلوب لدى المزوّد.",
      unavailable: "تعذّر الوصول إلى المزوّد أو أعاد خطأً من الخدمة الخلفية.",
      other: "فشل طلب المزوّد.",
    },
  },
  fa: {
    refresh: "تازه‌سازی",
    loading: "در حال درخواست داده از منبع…",
    refreshing: "در حال تازه‌سازی؛ تا پایان درخواست، آخرین پاسخ موفق نمایش داده می‌شود.",
    stale: "تازه‌سازی ناموفق بود؛ دادهٔ زیر آخرین پاسخ موفق است و بررسی فعلی منبع نیست.",
    lastSuccess: "زمان دریافت آخرین پاسخ معتبر در این مرورگر",
    empty: "منبع برای این بخش رکوردی برنگرداند.",
    retrying: (seconds, attempt, max) => `تلاش خودکار پس از ${seconds} ثانیه (تلاش ${attempt} از ${max}). می‌توانید دستی نیز تازه‌سازی کنید.`,
    retryGuidance: "اگر ادامه یافت، صبر کنید و از تازه‌سازی استفاده کنید. صفحه را پی‌درپی بارگذاری نکنید.",
    errors: {
      not_configured: "منبع سمت سرور در این استقرار پیکربندی نشده است.",
      unauthorized: "منبع اعتبارنامهٔ خواندن سمت سرور را نپذیرفت. تنظیمات استقرار را بررسی کنید.",
      forbidden: "منبع این درخواست خواندن را مجاز ندانست.",
      rate_limited: "منبع برای این درخواست محدودیت نرخ اعمال کرد. کمی صبر و سپس دوباره تلاش کنید.",
      invalid_request: "منبع پارامترهای درخواست را نپذیرفت.",
      conflict: "منبع گزارش داد که این درخواست با وضعیت فعلی آن ناسازگار است.",
      expired: "اعتبار منبع درخواستی پایان یافته است.",
      payload_too_large: "منبع درخواست را به‌دلیل عبور از محدودیت اندازه نپذیرفت.",
      invalid_response: "پاسخ منبع با شکل دادهٔ مستندشده سازگار نبود.",
      not_found: "منبع درخواستی در سرویس پیدا نشد.",
      unavailable: "دسترسی به منبع ممکن نبود یا سرویس بالادستی خطا داد.",
      other: "درخواست به منبع ناموفق بود.",
    },
  },
};

function formatLocalTime(value: string, locale: Locale): string {
  const timestamp = new Date(value);
  if (!Number.isFinite(timestamp.getTime())) return value;
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(timestamp);
}

type ResourcePanelProps<T> = {
  title: string;
  state: ResourceState<T>;
  onRefresh: () => void;
  isEmpty?: (data: T) => boolean;
  emptyMessage?: string;
  children: (data: T) => ReactNode;
};

export function ResourcePanel<T>({
  title,
  state,
  onRefresh,
  isEmpty,
  emptyMessage,
  children,
}: ResourcePanelProps<T>) {
  const locale = useCiccLocale()?.locale ?? "en";
  const copy = messages[locale];
  const titleId = useId().replaceAll(":", "");
  const isLoading = state.status === "loading";
  const hasData = state.data !== undefined;
  const empty = hasData && isEmpty?.(state.data as T) === true;

  return (
    <section className={styles.panel} aria-labelledby={`${titleId}-heading`}>
      <header className={styles.header}>
        <h2 id={`${titleId}-heading`}>{title}</h2>
        <button type="button" className={styles.refresh} onClick={onRefresh} disabled={isLoading}>
          {copy.refresh}
        </button>
      </header>

      <div aria-live="polite" aria-busy={isLoading}>
        {isLoading && !hasData && <p className={styles.status} role="status">{copy.loading}</p>}
        {isLoading && hasData && <p className={styles.notice} role="status">{copy.refreshing}</p>}
        {state.status === "error" && state.error && (
          <p className={styles.error} role="alert">{copy.errors[state.error.kind]}</p>
        )}
        {state.status === "error" && state.retry && (
          <p className={styles.notice} role="status">{copy.retrying(state.retry.nextRetryInSeconds, state.retry.attempt, state.retry.maxAttempts)}</p>
        )}
        {state.status === "error" && !state.retry && state.error && (state.error.kind === "rate_limited" || state.error.kind === "unavailable") && (
          <p className={styles.notice}>{copy.retryGuidance}</p>
        )}
        {state.status === "error" && hasData && (
          <p className={styles.staleNote}>{copy.stale}</p>
        )}
        {state.status === "ready" && empty && (
          <p className={styles.empty}>{emptyMessage ?? copy.empty}</p>
        )}
        {hasData && !empty && children(state.data as T)}
      </div>

      {state.checkedAt && (
        <p className={styles.checkedAt}>
          {copy.lastSuccess}: <time dateTime={state.checkedAt}>{formatLocalTime(state.checkedAt, locale)}</time>
        </p>
      )}
    </section>
  );
}
