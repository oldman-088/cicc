"use client";

import { useId, useState } from "react";
import type { Locale } from "../application/localization";
import { useCiccLocale } from "../application/CiccApplication";
import {
  integrationEndpoints,
  parseCoordinationAgents,
  parseCoordinationEvents,
  parseCoordinationMetrics,
  parseCoordinationTasks,
  type CoordinationAgent,
  type CoordinationEvent,
  type CoordinationMetrics,
  type CoordinationTask,
} from "../../lib/integration-api";
import { ResourcePanel } from "../integrations/ResourcePanel";
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
  const [query, setQuery] = useState("");
  const id = useId().replaceAll(":", "");
  const normalizedQuery = query.trim().toLocaleLowerCase(locale);
  const filteredTasks = tasks.filter((task) => {
    if (stateFilter !== "ALL" && task.state !== stateFilter) return false;
    if (!normalizedQuery) return true;
    return [task.task_id, task.title, task.kind, task.agent, task.repo, task.branch_ref]
      .some((value) => value?.toLocaleLowerCase(locale).includes(normalizedQuery));
  });

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
      </div>
      <p className={styles.scopeNote}>{messages.loadedScope} <bdi dir="ltr">{formatNumber(filteredTasks.length, locale)} / {formatNumber(tasks.length, locale)}</bdi> {messages.taskRecords}</p>
      {filteredTasks.length === 0 ? <p className={styles.inlineNote}>{messages.noMatches}</p> : (
        <ul className={styles.taskList}>
          {filteredTasks.map((task) => (
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
                </dl>
              </details>
            </li>
          ))}
        </ul>
      )}
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
        </div>
      </div>
    </div>
  );
}
