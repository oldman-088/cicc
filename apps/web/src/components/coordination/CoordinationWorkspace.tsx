"use client";

import { useId, useState } from "react";
import type { Locale } from "../application/localization";
import { useCiccLocale } from "../application/CiccApplication";
import {
  integrationEndpoints,
  parseCoordinationAgents,
  parseCoordinationEvents,
  parseCoordinationMetrics,
  parseCoordinationTaskEvents,
  parseCoordinationHealth,
  parseCoordinationTaskTrace,
  coordinationTaskEventsEndpoint,
  coordinationTaskTraceEndpoint,
  readIntegrationResource,
  parseCoordinationTasks,
  type CoordinationAgent,
  type CoordinationEvent,
  type CoordinationTaskEvent,
  type CoordinationMetrics,
  type CoordinationTask,
  type CoordinationHealth,
  type CoordinationTaskTrace,
} from "../../lib/integration-api";
import { ResourcePanel } from "../integrations/ResourcePanel";
import { TaskSubmissionPanel } from "./TaskSubmissionPanel";
import { useIntegrationResource } from "../integrations/useIntegrationResource";
import styles from "./CoordinationWorkspace.module.css";

type Messages = {
  eyebrow: string;
  title: string;
  intro: string;
  readOnly: string;
  scopeWarning: string;
  metrics: string;
  agents: string;
  tasks: string;
  events: string;
  totalTasks: string;
  agentsOnline: string;
  agentsRegistered: string;
  deadLettered: string;
  approvalsPending: string;
  deliveriesRecorded: string;
  stateCounts: string;
  emptyMetrics: string;
  emptyAgents: string;
  emptyTasks: string;
  emptyEvents: string;
  filterState: string;
  allStates: string;
  searchLoaded: string;
  taskRecords: string;
  loadedScope: string;
  noMatches: string;
  taskId: string;
  kind: string;
  state: string;
  priority: string;
  assignedAgent: string;
  noAgent: string;
  repository: string;
  branch: string;
  created: string;
  updated: string;
  deadLetter: string;
  viewEvents: string;
  hideEvents: string;
  loadingEvents: string;
  noEvents: string;
  eventsError: string;
  correlationKey: string;
  sortBy: string;
  sortNewest: string;
  sortPriority: string;
  sortState: string;
  previousPage: string;
  nextPage: string;
  pageLabel: string;
  copyLink: string;
  linkCopied: string;
  stale: string;
  health: string;
  agentStatus: string;
  specialization: string;
  capabilities: string;
  activeTasks: string;
  completedTasks: string;
  failedTasks: string;
  lastSeen: string;
  noTimestamp: string;
  coordHealth: string;
  healthOverall: string;
  healthCheckedAt: string;
  healthOnDemandNote: string;
  healthReasons: string;
  viewTrace: string;
  hideTrace: string;
  loadingTrace: string;
  traceError: string;
  traceDeliveries: string;
  traceApprovals: string;
  traceAttempts: string;
  traceEventId: string;
  noDeliveries: string;
  noApprovals: string;
  deliveryStatus: string;
  deliveryChannel: string;
  approvalStatus: string;
  requestedBy: string;
  decidedBy: string;
  eventName: string;
  action: string;
  sender: string;
  deliveryId: string;
  linkedTask: string;
  noValue: string;
  count: string;
};

const copy: Record<Locale, Messages> = {
  en: {
    eyebrow: "CICC / COORDINATION",
    title: "Agent Coordination",
    intro: "Read-only agent, task, metric, and webhook-event views from the configured coordination provider.",
    readOnly: "READ ONLY",
    scopeWarning: "Trusted single-tenant scope: these provider records have no tenant isolation, and this frontend does not authenticate users. Do not expose this deployment to untrusted users or multiple tenants.",
    metrics: "Coordination metrics",
    agents: "Registered agents",
    tasks: "Tasks returned by provider",
    events: "Webhook events received",
    totalTasks: "Tasks total",
    agentsOnline: "Agents online",
    agentsRegistered: "Agents registered",
    deadLettered: "Dead-lettered tasks",
    approvalsPending: "Approvals pending",
    deliveriesRecorded: "Deliveries recorded",
    stateCounts: "Task counts by state",
    emptyMetrics: "The provider returned no metric fields for this section.",
    emptyAgents: "The provider returned no agent records.",
    emptyTasks: "The provider returned no task records.",
    emptyEvents: "The provider returned no webhook event records.",
    filterState: "Filter loaded tasks by state",
    allStates: "All states",
    searchLoaded: "Search the returned task records",
    taskRecords: "task records",
    loadedScope: "Filters apply only to the task records returned in this response (maximum 100).",
    noMatches: "No returned task records match the selected filters.",
    taskId: "Task ID",
    kind: "Kind",
    state: "State",
    priority: "Priority",
    assignedAgent: "Assigned agent",
    noAgent: "No agent reported",
    repository: "Repository",
    branch: "Branch",
    created: "Created at",
    updated: "Updated at",
    deadLetter: "Dead letter",
    viewEvents: "View lifecycle events",
    hideEvents: "Hide lifecycle events",
    loadingEvents: "Loading task events…",
    noEvents: "The provider returned no lifecycle events for this task.",
    eventsError: "Task events could not be loaded from the provider.",
    correlationKey: "Correlation (idempotency) key",
    coordHealth: "Coordination health",
    healthOverall: "Overall",
    healthCheckedAt: "Checked at",
    healthOnDemandNote: "Checked on demand when this page loads or is refreshed — this is not continuous monitoring.",
    healthReasons: "Reasons reported by the provider",
    viewTrace: "View task trace",
    hideTrace: "Hide task trace",
    loadingTrace: "Loading task trace…",
    traceError: "Task trace could not be loaded from the provider.",
    traceDeliveries: "Delivery attempts",
    traceApprovals: "Approvals",
    traceAttempts: "Attempts",
    traceEventId: "Event ID",
    noDeliveries: "The provider recorded no delivery attempts for this task.",
    noApprovals: "The provider recorded no approvals for this task.",
    deliveryStatus: "Delivery status",
    deliveryChannel: "Channel",
    approvalStatus: "Approval status",
    requestedBy: "Requested by",
    decidedBy: "Decided by",
    sortBy: "Sort tasks", sortNewest: "Newest first", sortPriority: "Highest priority", sortState: "State (A–Z)", previousPage: "Previous page", nextPage: "Next page", pageLabel: "Page", copyLink: "Copy task link", linkCopied: "Link copied",
    stale: "Stale per provider",
    health: "Provider health",
    agentStatus: "Provider-reported status",
    specialization: "Specialization",
    capabilities: "Capabilities",
    activeTasks: "Active tasks",
    completedTasks: "Completed tasks",
    failedTasks: "Failed tasks",
    lastSeen: "Provider timestamp",
    noTimestamp: "Not provided",
    eventName: "Event",
    action: "Action",
    sender: "Sender",
    deliveryId: "Delivery ID",
    linkedTask: "Task ID from event mapping",
    noValue: "Not provided",
    count: "Count",
  },
  ar: {
    eyebrow: "CICC / التنسيق",
    title: "تنسيق الوكلاء",
    intro: "عرض للقراءة فقط للوكلاء والمهام والمقاييس وأحداث الويب هوك من مزوّد التنسيق المضبوط.",
    readOnly: "للقراءة فقط",
    scopeWarning: "نطاق موثوق لمستأجر واحد: لا تتضمن سجلات المزوّد عزل المستأجرين، ولا تصادق هذه الواجهة على المستخدمين. لا تعرض هذا النشر لمستخدمين غير موثوقين أو لعدة مستأجرين.",
    metrics: "مقاييس التنسيق",
    agents: "الوكلاء المسجّلون",
    tasks: "المهام التي أعادها المزوّد",
    events: "أحداث الويب هوك المستلمة",
    totalTasks: "إجمالي المهام",
    agentsOnline: "الوكلاء المتصلون",
    agentsRegistered: "الوكلاء المسجّلون",
    deadLettered: "المهام في قائمة العزل",
    approvalsPending: "الموافقات المعلّقة",
    deliveriesRecorded: "عمليات التسليم المسجّلة",
    stateCounts: "عدد المهام حسب الحالة",
    emptyMetrics: "لم يُرجع المزوّد حقول مقاييس لهذا القسم.",
    emptyAgents: "لم يُرجع المزوّد سجلات للوكلاء.",
    emptyTasks: "لم يُرجع المزوّد سجلات للمهام.",
    emptyEvents: "لم يُرجع المزوّد سجلات لأحداث الويب هوك.",
    filterState: "تصفية المهام المُعادة حسب الحالة",
    allStates: "كل الحالات",
    searchLoaded: "البحث في سجلات المهام المُعادة",
    taskRecords: "سجلات مهام",
    loadedScope: "تُطبّق عوامل التصفية على سجلات المهام المُعادة في هذه الاستجابة فقط (حد أقصى 100).",
    noMatches: "لا تطابق أي سجلات مهام مُعادة عوامل التصفية المختارة.",
    taskId: "معرّف المهمة",
    kind: "النوع",
    state: "الحالة",
    priority: "الأولوية",
    assignedAgent: "الوكيل المعيّن",
    noAgent: "لم يُذكر وكيل",
    repository: "المستودع",
    branch: "الفرع",
    created: "وقت الإنشاء",
    updated: "وقت التحديث",
    deadLetter: "قائمة العزل",
    viewEvents: "عرض أحداث دورة الحياة",
    hideEvents: "إخفاء أحداث دورة الحياة",
    loadingEvents: "جارٍ تحميل أحداث المهمة…",
    noEvents: "لم يُرجع المزوّد أحداثاً لدورة حياة هذه المهمة.",
    eventsError: "تعذّر تحميل أحداث المهمة من المزوّد.",
    correlationKey: "مفتاح الارتباط (عدم التكرار)",
    coordHealth: "صحة التنسيق",
    healthOverall: "الإجمالي",
    healthCheckedAt: "وقت الفحص",
    healthOnDemandNote: "يُفحص عند الطلب عند تحميل هذه الصفحة أو تحديثها — وليس مراقبة مستمرة.",
    healthReasons: "الأسباب التي أبلغ عنها المزوّد",
    viewTrace: "عرض تتبّع المهمة",
    hideTrace: "إخفاء تتبّع المهمة",
    loadingTrace: "جارٍ تحميل تتبّع المهمة…",
    traceError: "تعذّر تحميل تتبّع المهمة من المزوّد.",
    traceDeliveries: "محاولات التسليم",
    traceApprovals: "الموافقات",
    traceAttempts: "المحاولات",
    traceEventId: "معرّف الحدث",
    noDeliveries: "لم يسجّل المزوّد محاولات تسليم لهذه المهمة.",
    noApprovals: "لم يسجّل المزوّد موافقات لهذه المهمة.",
    deliveryStatus: "حالة التسليم",
    deliveryChannel: "القناة",
    approvalStatus: "حالة الموافقة",
    requestedBy: "طلبها",
    decidedBy: "بتّ فيها",
    sortBy: "ترتيب المهام", sortNewest: "الأحدث أولاً", sortPriority: "الأولوية الأعلى", sortState: "الحالة (أ–ي)", previousPage: "الصفحة السابقة", nextPage: "الصفحة التالية", pageLabel: "صفحة", copyLink: "نسخ رابط المهمة", linkCopied: "نُسخ الرابط",
    stale: "قديم بحسب المزوّد",
    health: "صحة الوكيل بحسب المزوّد",
    agentStatus: "الحالة كما أبلغ عنها المزوّد",
    specialization: "التخصص",
    capabilities: "الإمكانات",
    activeTasks: "المهام النشطة",
    completedTasks: "المهام المكتملة",
    failedTasks: "المهام الفاشلة",
    lastSeen: "الطابع الزمني كما أعاده المزوّد",
    noTimestamp: "غير متوفر",
    eventName: "الحدث",
    action: "الإجراء",
    sender: "المرسل",
    deliveryId: "معرّف التسليم",
    linkedTask: "معرّف المهمة من ربط الحدث",
    noValue: "غير متوفر",
    count: "العدد",
  },
  fa: {
    eyebrow: "CICC / هماهنگی",
    title: "هماهنگی عامل‌ها",
    intro: "نمای فقط‌خواندنی عامل‌ها، وظایف، معیارها و رویدادهای وب‌هوک از منبع هماهنگی پیکربندی‌شده.",
    readOnly: "فقط‌خواندنی",
    scopeWarning: "محدودهٔ استقرار مورداعتماد و تک‌مستاجری: رکوردهای منبع جداسازی مستأجر ندارند و این رابط کاربران را احراز هویت نمی‌کند. این استقرار را در معرض کاربران نامطمئن یا چند مستأجر قرار ندهید.",
    metrics: "معیارهای هماهنگی",
    agents: "عامل‌های ثبت‌شده",
    tasks: "وظایف بازگشتی از منبع",
    events: "رویدادهای وب‌هوک دریافت‌شده",
    totalTasks: "مجموع وظایف",
    agentsOnline: "عامل‌های آنلاین",
    agentsRegistered: "عامل‌های ثبت‌شده",
    deadLettered: "وظایف صف مرده",
    approvalsPending: "تأییدهای در انتظار",
    deliveriesRecorded: "تحویل‌های ثبت‌شده",
    stateCounts: "شمار وظایف به تفکیک وضعیت",
    emptyMetrics: "منبع برای این بخش فیلد معیاری برنگرداند.",
    emptyAgents: "منبع هیچ رکورد عاملی برنگرداند.",
    emptyTasks: "منبع هیچ رکورد وظیفه‌ای برنگرداند.",
    emptyEvents: "منبع هیچ رویداد وب‌هوکی برنگرداند.",
    filterState: "فیلتر وظایف بازگشتی بر اساس وضعیت",
    allStates: "همهٔ وضعیت‌ها",
    searchLoaded: "جست‌وجو در رکوردهای وظیفهٔ بازگشتی",
    taskRecords: "رکورد وظیفه",
    loadedScope: "فیلترها فقط روی رکوردهای بازگشتی همین پاسخ اعمال می‌شوند (حداکثر ۱۰۰).",
    noMatches: "هیچ‌یک از رکوردهای بازگشتی با فیلترهای انتخاب‌شده هم‌خوان نیست.",
    taskId: "شناسهٔ وظیفه",
    kind: "نوع",
    state: "وضعیت",
    priority: "اولویت",
    assignedAgent: "عامل تخصیص‌یافته",
    noAgent: "عاملی گزارش نشده است",
    repository: "مخزن",
    branch: "شاخه",
    created: "زمان ایجاد",
    updated: "زمان به‌روزرسانی",
    deadLetter: "صف مرده",
    viewEvents: "مشاهدهٔ رویدادهای چرخهٔ حیات",
    hideEvents: "پنهان‌کردن رویدادهای چرخهٔ حیات",
    loadingEvents: "در حال بارگذاری رویدادهای وظیفه…",
    noEvents: "منبع برای این وظیفه رویداد چرخهٔ حیاتی برنگرداند.",
    eventsError: "بارگذاری رویدادهای وظیفه از منبع ممکن نشد.",
    correlationKey: "کلید هم‌بستگی (یکتایی)",
    coordHealth: "سلامت هماهنگی",
    healthOverall: "کلی",
    healthCheckedAt: "زمان بررسی",
    healthOnDemandNote: "هنگام بارگذاری یا بازخوانی این صفحه و بر اساس درخواست بررسی می‌شود — این پایش پیوسته نیست.",
    healthReasons: "دلایل گزارش‌شده از سوی منبع",
    viewTrace: "مشاهدهٔ ردیابی وظیفه",
    hideTrace: "پنهان‌کردن ردیابی وظیفه",
    loadingTrace: "در حال بارگذاری ردیابی وظیفه…",
    traceError: "بارگذاری ردیابی وظیفه از منبع ممکن نشد.",
    traceDeliveries: "تلاش‌های تحویل",
    traceApprovals: "تأییدها",
    traceAttempts: "تلاش‌ها",
    traceEventId: "شناسهٔ رویداد",
    noDeliveries: "منبع برای این وظیفه هیچ تلاش تحویلی ثبت نکرده است.",
    noApprovals: "منبع برای این وظیفه هیچ تأییدی ثبت نکرده است.",
    deliveryStatus: "وضعیت تحویل",
    deliveryChannel: "کانال",
    approvalStatus: "وضعیت تأیید",
    requestedBy: "درخواست‌کننده",
    decidedBy: "تصمیم‌گیرنده",
    sortBy: "مرتب‌سازی وظایف", sortNewest: "تازه‌ترین اول", sortPriority: "بالاترین اولویت", sortState: "وضعیت (الفبا)", previousPage: "صفحهٔ قبل", nextPage: "صفحهٔ بعد", pageLabel: "صفحه", copyLink: "کپی پیوند وظیفه", linkCopied: "پیوند کپی شد",
    stale: "طبق منبع قدیمی است",
    health: "سلامت عامل طبق منبع",
    agentStatus: "وضعیت گزارش‌شده از منبع",
    specialization: "تخصص",
    capabilities: "قابلیت‌ها",
    activeTasks: "وظایف فعال",
    completedTasks: "وظایف تکمیل‌شده",
    failedTasks: "وظایف ناموفق",
    lastSeen: "زمان گزارش‌شده از منبع",
    noTimestamp: "ارائه نشده است",
    eventName: "رویداد",
    action: "اقدام",
    sender: "فرستنده",
    deliveryId: "شناسهٔ تحویل",
    linkedTask: "شناسهٔ وظیفه از نگاشت رویداد",
    noValue: "ارائه نشده است",
    count: "شمار",
  },
};

const taskStates = [
  "CREATED",
  "VALIDATING",
  "QUEUED",
  "ASSIGNED",
  "DELIVERING",
  "ACKNOWLEDGED",
  "RUNNING",
  "WAITING_FOR_APPROVAL",
  "COMPLETED",
  "FAILED",
  "RETRYING",
  "BLOCKED",
  "CANCELLED",
  "EXPIRED",
] as const;

function formatNumber(value: number, locale: Locale): string {
  return new Intl.NumberFormat(locale).format(value);
}

function formatTimestamp(value: string | null, locale: Locale, fallback: string): string {
  if (!value) return fallback;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function MetricContent({ data, locale, messages }: { data: CoordinationMetrics; locale: Locale; messages: Messages }) {
  const summary = [
    [messages.totalTasks, data.tasks_total],
    [messages.agentsOnline, data.agents_online],
    [messages.agentsRegistered, data.agents_registered],
    [messages.deadLettered, data.dead_lettered],
    [messages.approvalsPending, data.approvals_pending],
    [messages.deliveriesRecorded, data.deliveries_total],
  ] as const;
  const states = Object.entries(data.by_state).sort(([a], [b]) => a.localeCompare(b));

  return (
    <div className={styles.metricsContent}>
      <dl className={styles.metricGrid}>
        {summary.map(([label, value]) => (
          <div className={styles.metricCard} key={label}>
            <dt>{label}</dt><dd>{formatNumber(value, locale)}</dd>
          </div>
        ))}
      </dl>
      <section className={styles.stateCounts}>
        <h3>{messages.stateCounts}</h3>
        {states.length === 0 ? <p className={styles.inlineNote}>{messages.emptyMetrics}</p> : (
          <ul>
            {states.map(([state, count]) => (
              <li key={state}>
                <span><bdi dir="ltr">{state}</bdi></span><strong>{formatNumber(count, locale)}</strong>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function AgentContent({ agents, locale, messages }: { agents: CoordinationAgent[]; locale: Locale; messages: Messages }) {
  return (
    <ul className={styles.agentList}>
      {agents.map((agent) => (
        <li key={agent.agent} className={styles.recordCard}>
          <div className={styles.cardHeading}>
            <div className={styles.agentHeading}>
              <h3><bdi dir="ltr">{agent.agent}</bdi></h3>
              {agent.specialization && <p dir="auto">{agent.specialization}</p>}
            </div>
            <div className={styles.badges}>
              <span className={styles.statusTag}><bdi dir="auto">{agent.status}</bdi></span>
              <span className={styles.statusTag}><bdi dir="ltr">{agent.health}</bdi></span>
              {agent.stale && <span className={`${styles.statusTag} ${styles.warningTag}`}>{messages.stale}</span>}
            </div>
          </div>
          <dl className={styles.smallMeta}>
            <div><dt>{messages.agentStatus}</dt><dd><bdi dir="auto">{agent.status}</bdi></dd></div>
            <div><dt>{messages.health}</dt><dd><bdi dir="ltr">{agent.health}</bdi></dd></div>
            <div><dt>{messages.lastSeen} · <code><bdi dir="ltr">last_heartbeat</bdi></code></dt><dd>{formatTimestamp(agent.last_heartbeat, locale, messages.noTimestamp)}</dd></div>
            <div><dt>{messages.activeTasks}</dt><dd>{formatNumber(agent.active_tasks, locale)}</dd></div>
            <div><dt>{messages.completedTasks}</dt><dd>{formatNumber(agent.completed, locale)}</dd></div>
            <div><dt>{messages.failedTasks}</dt><dd>{formatNumber(agent.failed, locale)}</dd></div>
          </dl>
          {agent.capabilities.length > 0 && (
            <div className={styles.capabilities}>
              <span>{messages.capabilities}</span>
              <ul>{agent.capabilities.map((capability) => <li key={capability}><bdi dir="auto">{capability}</bdi></li>)}</ul>
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

function TaskContent({
  tasks,
  locale,
  messages,
}: {
  tasks: CoordinationTask[];
  locale: Locale;
  messages: Messages;
}) {
  const [stateFilter, setStateFilter] = useState("ALL");
  const [query, setQuery] = useState(() => (typeof window === "undefined" ? "" : new URLSearchParams(window.location.search).get("task") ?? ""));
  const [sortBy, setSortBy] = useState<"newest" | "priority" | "state">("newest");
  const [page, setPage] = useState(0);
  const [copied, setCopied] = useState(false);
  const id = useId().replaceAll(":", "");
  const normalizedQuery = query.trim().toLocaleLowerCase(locale);
  const filteredTasks = tasks.filter((task) => {
    if (stateFilter !== "ALL" && task.state !== stateFilter) return false;
    if (!normalizedQuery) return true;
    return [task.task_id, task.title, task.kind, task.agent, task.repo, task.branch_ref]
      .some((value) => value?.toLocaleLowerCase(locale).includes(normalizedQuery));
  }).sort((a, b) => sortBy === "priority" ? b.priority - a.priority : sortBy === "state" ? a.state.localeCompare(b.state) : (b.created_at ?? "").localeCompare(a.created_at ?? ""));
  const pageSize = 10;
  const pageCount = Math.max(1, Math.ceil(filteredTasks.length / pageSize));
  const safePage = Math.min(page, pageCount - 1);
  const visibleTasks = filteredTasks.slice(safePage * pageSize, safePage * pageSize + pageSize);

  return (
    <div>
      <div className={styles.filterBar}>
        <label htmlFor={`${id}-state`}>
          <span>{messages.filterState}</span>
          <select id={`${id}-state`} dir="ltr" value={stateFilter} onChange={(event) => setStateFilter(event.target.value)}>
            <option value="ALL">{messages.allStates}</option>
            {taskStates.map((state) => <option key={state} value={state}>{state}</option>)}
          </select>
        </label>
        <label htmlFor={`${id}-query`}>
          <span>{messages.searchLoaded}</span>
          <input id={`${id}-query`} dir="auto" type="search" value={query} onChange={(event) => setQuery(event.target.value)} />
        </label>
        <label htmlFor={`${id}-sort`}>
          <span>{messages.sortBy}</span>
          <select id={`${id}-sort`} value={sortBy} onChange={(event) => { setSortBy(event.target.value as typeof sortBy); setPage(0); }}>
            <option value="newest">{messages.sortNewest}</option>
            <option value="priority">{messages.sortPriority}</option>
            <option value="state">{messages.sortState}</option>
          </select>
        </label>
      </div>
      <p className={styles.scopeNote}>{messages.loadedScope} <bdi dir="ltr">{formatNumber(filteredTasks.length, locale)} / {formatNumber(tasks.length, locale)}</bdi> {messages.taskRecords}</p>
      {filteredTasks.length === 0 ? <p className={styles.inlineNote}>{messages.noMatches}</p> : (
        <ul className={styles.taskList}>
          {visibleTasks.map((task) => (
            <li key={task.task_id} className={styles.recordCard}>
              <details>
                <summary>
                  <span className={styles.taskTitle}>{task.title ? <bdi dir="auto">{task.title}</bdi> : <bdi dir="ltr">{task.task_id}</bdi>}</span>
                  <span className={styles.badges}>
                    <span className={styles.statusTag}><bdi dir="ltr">{task.state}</bdi></span>
                    {task.dead_letter && <span className={`${styles.statusTag} ${styles.warningTag}`}>{messages.deadLetter}</span>}
                  </span>
                </summary>
                <dl className={styles.smallMeta}>
                  <div><dt>{messages.taskId}</dt><dd><code><bdi dir="ltr">{task.task_id}</bdi></code></dd></div>
                  <div><dt>{messages.kind}</dt><dd><bdi dir="ltr">{task.kind}</bdi></dd></div>
                  <div><dt>{messages.state}</dt><dd><bdi dir="ltr">{task.state}</bdi></dd></div>
                  <div><dt>{messages.priority}</dt><dd>{formatNumber(task.priority, locale)}</dd></div>
                  <div><dt>{messages.assignedAgent}</dt><dd>{task.agent ? <bdi dir="ltr">{task.agent}</bdi> : messages.noAgent}</dd></div>
                  <div><dt>{messages.repository}</dt><dd>{task.repo ? <bdi dir="ltr">{task.repo}</bdi> : messages.noValue}</dd></div>
                  <div><dt>{messages.branch}</dt><dd>{task.branch_ref ? <bdi dir="ltr">{task.branch_ref}</bdi> : messages.noValue}</dd></div>
                  <div><dt>{messages.created}</dt><dd>{formatTimestamp(task.created_at, locale, messages.noTimestamp)}</dd></div>
                  <div><dt>{messages.updated}</dt><dd>{formatTimestamp(task.updated_at, locale, messages.noTimestamp)}</dd></div>
                  {task.idempotency_key && <div><dt>{messages.correlationKey}</dt><dd><code><bdi dir="ltr">{task.idempotency_key}</bdi></code></dd></div>}
                </dl>
                <button type="button" onClick={() => { const link = `${window.location.pathname}?task=${encodeURIComponent(task.task_id)}`; void navigator.clipboard?.writeText(`${window.location.origin}${link}`).then(() => setCopied(true)).catch(() => undefined); }}>{messages.copyLink}</button>
                {copied && <span role="status"> {messages.linkCopied}</span>}
                <TaskEvents taskId={task.task_id} locale={locale} messages={messages} />
                <TaskTrace taskId={task.task_id} locale={locale} messages={messages} />
              </details>
            </li>
          ))}
        </ul>
      )}
      {pageCount > 1 && (
        <nav aria-label={messages.pageLabel}>
          <button type="button" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>{messages.previousPage}</button>{" "}
          <span>{messages.pageLabel} {safePage + 1} / {pageCount}</span>{" "}
          <button type="button" disabled={safePage >= pageCount - 1} onClick={() => setPage(safePage + 1)}>{messages.nextPage}</button>
        </nav>
      )}
    </div>
  );
}

function HealthContent({ data, locale, messages }: { data: CoordinationHealth; locale: Locale; messages: Messages }) {
  const degraded = data.overall !== "healthy";
  return (
    <div>
      <p>
        <strong>{messages.healthOverall}:</strong>{" "}
        <span className={degraded ? `${styles.statusTag} ${styles.warningTag}` : styles.statusTag}>
          <bdi dir="ltr">{data.overall}</bdi>
        </span>
        {data.at && <> · {messages.healthCheckedAt}: {formatTimestamp(data.at, locale, messages.noTimestamp)}</>}
      </p>
      <p className={styles.scopeNote}>{messages.healthOnDemandNote}</p>
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
      {data.reasons.length > 0 && (
        <>
          <h3>{messages.healthReasons}</h3>
          <ul>{data.reasons.map((reason) => <li key={reason}><bdi dir="auto">{reason}</bdi></li>)}</ul>
        </>
      )}
    </div>
  );
}

function TaskTrace({ taskId, locale, messages }: { taskId: string; locale: Locale; messages: Messages }) {
  const [state, setState] = useState<{ phase: "idle" | "loading" | "ready" | "error"; trace?: CoordinationTaskTrace }>({ phase: "idle" });
  const load = () => {
    if (state.phase === "loading") return;
    if (state.phase === "ready") { setState({ phase: "idle" }); return; }
    setState({ phase: "loading" });
    void readIntegrationResource(coordinationTaskTraceEndpoint(taskId), parseCoordinationTaskTrace, new AbortController().signal)
      .then((trace) => setState({ phase: "ready", trace }))
      .catch(() => setState({ phase: "error" }));
  };
  const trace = state.trace;
  return (
    <div>
      <button type="button" onClick={load} aria-expanded={state.phase === "ready"}>
        {state.phase === "ready" ? messages.hideTrace : messages.viewTrace}
      </button>
      <div aria-live="polite">
        {state.phase === "loading" && <p>{messages.loadingTrace}</p>}
        {state.phase === "error" && <p role="alert">{messages.traceError}</p>}
        {state.phase === "ready" && trace && (
          <div>
            <dl className={styles.smallMeta}>
              <div><dt>{messages.state}</dt><dd><bdi dir="ltr">{trace.state}</bdi></dd></div>
              <div><dt>{messages.assignedAgent}</dt><dd>{trace.agent ? <bdi dir="auto">{trace.agent}</bdi> : messages.noAgent}</dd></div>
              <div><dt>{messages.traceAttempts}</dt><dd>{formatNumber(trace.attempts, locale)}</dd></div>
              <div><dt>{messages.deadLetter}</dt><dd>{trace.dead_letter ? "true" : "false"}</dd></div>
              <div><dt>{messages.correlationKey}</dt><dd>{trace.correlation.idempotency_key ? <code><bdi dir="ltr">{trace.correlation.idempotency_key}</bdi></code> : messages.noValue}</dd></div>
              <div><dt>{messages.traceEventId}</dt><dd>{trace.correlation.event_id ? <code><bdi dir="ltr">{trace.correlation.event_id}</bdi></code> : messages.noValue}</dd></div>
            </dl>
            {trace.events.length > 0 ? (
              <ol>{trace.events.map((event) => (
                <li key={event.id}><bdi dir="ltr">{event.kind}</bdi>{event.at && <> · {formatTimestamp(event.at, locale, messages.noTimestamp)}</>}{event.detail && <><br /><bdi dir="auto">{event.detail}</bdi></>}</li>
              ))}</ol>
            ) : <p>{messages.noEvents}</p>}
            <h4>{messages.traceDeliveries}</h4>
            {trace.deliveries.length > 0 ? (
              <ul>{trace.deliveries.map((delivery) => (
                <li key={delivery.id}>
                  <bdi dir="ltr">{delivery.status}</bdi>
                  {delivery.channel && <> · {messages.deliveryChannel}: <bdi dir="auto">{delivery.channel}</bdi></>}
                  {" · "}{messages.traceAttempts}: {formatNumber(delivery.attempt, locale)}
                  {delivery.at && <> · {formatTimestamp(delivery.at, locale, messages.noTimestamp)}</>}
                </li>
              ))}</ul>
            ) : <p>{messages.noDeliveries}</p>}
            <h4>{messages.traceApprovals}</h4>
            {trace.approvals.length > 0 ? (
              <ul>{trace.approvals.map((approval) => (
                <li key={approval.id}>
                  <bdi dir="ltr">{approval.status}</bdi>
                  {approval.requested_by && <> · {messages.requestedBy}: <bdi dir="auto">{approval.requested_by}</bdi></>}
                  {approval.decided_by && <> · {messages.decidedBy}: <bdi dir="auto">{approval.decided_by}</bdi></>}
                  {approval.at && <> · {formatTimestamp(approval.at, locale, messages.noTimestamp)}</>}
                </li>
              ))}</ul>
            ) : <p>{messages.noApprovals}</p>}
          </div>
        )}
      </div>
    </div>
  );
}

function TaskEvents({ taskId, locale, messages }: { taskId: string; locale: Locale; messages: Messages }) {
  const [state, setState] = useState<{ phase: "idle" | "loading" | "ready" | "error"; events?: CoordinationTaskEvent[] }>({ phase: "idle" });
  const load = () => {
    if (state.phase === "loading") return;
    if (state.phase === "ready") { setState({ phase: "idle" }); return; }
    setState({ phase: "loading" });
    void readIntegrationResource(coordinationTaskEventsEndpoint(taskId), parseCoordinationTaskEvents, new AbortController().signal)
      .then((data) => setState({ phase: "ready", events: data.events }))
      .catch(() => setState({ phase: "error" }));
  };
  return (
    <div>
      <button type="button" onClick={load} aria-expanded={state.phase === "ready"}>
        {state.phase === "ready" ? messages.hideEvents : messages.viewEvents}
      </button>
      <div aria-live="polite">
        {state.phase === "loading" && <p>{messages.loadingEvents}</p>}
        {state.phase === "error" && <p role="alert">{messages.eventsError}</p>}
        {state.phase === "ready" && (state.events && state.events.length > 0 ? (
          <ol>{state.events.map((event, index) => (
            <li key={index}><bdi dir="ltr">{event.kind}</bdi>{event.at && <> · {formatTimestamp(event.at, locale, messages.noTimestamp)}</>}{event.detail && <><br /><bdi dir="auto">{event.detail}</bdi></>}</li>
          ))}</ol>
        ) : <p>{messages.noEvents}</p>)}
      </div>
    </div>
  );
}

function EventContent({ events, locale, messages }: { events: CoordinationEvent[]; locale: Locale; messages: Messages }) {
  return (
    <ol className={styles.eventList}>
      {events.map((event) => (
        <li key={event.delivery_id} className={styles.recordCard}>
          <div className={styles.cardHeading}>
            <h3><bdi dir="ltr">{event.event}</bdi></h3>
            {event.action && <span className={styles.statusTag}><bdi dir="auto">{event.action}</bdi></span>}
          </div>
          <dl className={styles.smallMeta}>
            <div><dt>{messages.deliveryId}</dt><dd><code><bdi dir="ltr">{event.delivery_id}</bdi></code></dd></div>
            <div><dt>{messages.sender}</dt><dd>{event.sender ? <bdi dir="auto">{event.sender}</bdi> : messages.noValue}</dd></div>
            <div><dt>{messages.repository}</dt><dd>{event.repo ? <bdi dir="ltr">{event.repo}</bdi> : messages.noValue}</dd></div>
            <div><dt>{messages.linkedTask}</dt><dd>{event.task_id ? <bdi dir="ltr">{event.task_id}</bdi> : messages.noValue}</dd></div>
          </dl>
          {event.received_at && <time className={styles.eventTime} dateTime={event.received_at}>{formatTimestamp(event.received_at, locale, messages.noTimestamp)}</time>}
        </li>
      ))}
    </ol>
  );
}

export function CoordinationWorkspace() {
  const locale = useCiccLocale()?.locale ?? "en";
  const text = copy[locale];
  const id = useId().replaceAll(":", "");
  const metrics = useIntegrationResource(integrationEndpoints.coordinationMetrics, parseCoordinationMetrics);
  const agents = useIntegrationResource(integrationEndpoints.coordinationAgents, parseCoordinationAgents);
  const tasks = useIntegrationResource(integrationEndpoints.coordinationTasks, parseCoordinationTasks);
  const events = useIntegrationResource(integrationEndpoints.coordinationEvents, parseCoordinationEvents);
  const health = useIntegrationResource(integrationEndpoints.coordinationHealth, parseCoordinationHealth);

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
        <ResourcePanel title={text.metrics} state={metrics.state} onRefresh={metrics.refresh}>
          {(data) => <MetricContent data={data} locale={locale} messages={text} />}
        </ResourcePanel>

        <ResourcePanel title={text.coordHealth} state={health.state} onRefresh={health.refresh}>
          {(data) => <HealthContent data={data} locale={locale} messages={text} />}
        </ResourcePanel>

        <ResourcePanel
          title={text.agents}
          state={agents.state}
          onRefresh={agents.refresh}
          isEmpty={(data) => data.agents.length === 0}
          emptyMessage={text.emptyAgents}
        >
          {(data) => <AgentContent agents={data.agents} locale={locale} messages={text} />}
        </ResourcePanel>

        <div className={styles.widePanel}>
          <ResourcePanel
            title={text.tasks}
            state={tasks.state}
            onRefresh={tasks.refresh}
            isEmpty={(data) => data.tasks.length === 0}
            emptyMessage={text.emptyTasks}
          >
            {(data) => <TaskContent tasks={data.tasks} locale={locale} messages={text} />}
          </ResourcePanel>
        </div>

        <div className={styles.widePanel}>
          <ResourcePanel
            title={text.events}
            state={events.state}
            onRefresh={events.refresh}
            isEmpty={(data) => data.events.length === 0}
            emptyMessage={text.emptyEvents}
          >
            {(data) => <EventContent events={data.events} locale={locale} messages={text} />}
          </ResourcePanel>
        <TaskSubmissionPanel />
        </div>
      </div>
    </div>
  );
}
