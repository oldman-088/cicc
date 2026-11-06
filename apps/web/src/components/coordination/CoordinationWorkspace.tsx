"use client";

import { useId, useState, type FormEvent } from "react";
import type { Locale } from "../application/localization";
import { useCiccLocale } from "../application/CiccApplication";
import {
  createCoordinationTask,
  integrationEndpoints,
  parseCoordinationAgents,
  parseCoordinationEvents,
  parseCoordinationHealth,
  parseCoordinationMetrics,
  parseCoordinationTaskTrace,
  parseCoordinationTasks,
  parseCoordinationWriteCapabilities,
  IntegrationApiError,
  type CoordinationAgent,
  type CoordinationEvent,
  type CoordinationHealth,
  type CoordinationHealthStatus,
  type CoordinationMetrics,
  type CoordinationTask,
  type CoordinationTaskTrace,
  type CoordinationWriteCapabilities,
  type CreateCoordinationTaskResult,
} from "../../lib/integration-api";
import { ResourcePanel } from "../integrations/ResourcePanel";
import { useIntegrationResource, type ResourceState } from "../integrations/useIntegrationResource";
import styles from "./CoordinationWorkspace.module.css";

type BaseMessages = {
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
  health: string;
  healthOverall: string;
  healthComponents: string;
  healthReasons: string;
  healthNoComponents: string;
  healthNoReasons: string;
  healthLastOperations: string;
  healthCheckedAt: string;
  healthLastWebhook: string;
  healthLastSyncSuccess: string;
  healthLastSyncAttempt: string;
  healthLastTaskEvent: string;
  healthOnDemandNote: string;
  healthStatus: Record<CoordinationHealthStatus, string>;
  healthField: string;
  healthDetail: string;
  traceOpen: string;
  traceClose: string;
  trace: string;
  traceSummary: string;
  traceNoEntries: string;
  traceEvents: string;
  traceDeliveries: string;
  traceApprovals: string;
  traceCorrelation: string;
  traceIdempotencyKey: string;
  traceEventId: string;
  traceAttempts: string;
  traceAgent: string;
  traceAt: string;
  traceKind: string;
  traceDetail: string;
  traceChannel: string;
  traceQueue: string;
  traceMessageId: string;
  traceDeliveryStatus: string;
  traceAttempt: string;
  traceRequestedBy: string;
  traceDecidedBy: string;
  traceEmptyEvents: string;
  traceEmptyDeliveries: string;
  traceEmptyApprovals: string;
  taskIdempotencyKey: string;
};

type WorkflowMessages = {
  taskCreation: string;
  taskCreationSummary: string;
  taskCreationDisabled: string;
  taskKindLabel: string;
  taskTitleLabel: string;
  taskPriorityLabel: string;
  taskPayloadLabel: string;
  taskPayloadHint: string;
  taskPayloadInvalid: string;
  taskKindHint: string;
  taskRequiresApproval: string;
  taskCreateSubmit: string;
  taskCreating: string;
  taskCreated: string;
  taskCreatedDuplicate: string;
  taskCreatedState: string;
  taskCreateError: string;
  taskCreateUncertain: string;
  taskRouting: string;
  taskRouteVia: string;
  taskRouteRule: string;
  taskRouteScore: string;
  taskRouteCandidates: string;
  taskRouteReasons: string;
  taskRoutingUnreported: string;
  taskResult: string;
  taskResultEmpty: string;
  taskProgress: string;
  taskAttempts: string;
  pageNavigation: string;
  pageSize: string;
  previousPage: string;
  nextPage: string;
  page: string;
};

type Messages = BaseMessages & WorkflowMessages;

const copy: Record<Locale, BaseMessages> = {
  en: {
    eyebrow: "CICC / COORDINATION",
    title: "Agent Coordination",
    intro: "Provider-backed agent, task, metric, and webhook-event views. Task creation is available only when its server-side gate is enabled; routing and other task-state writes are not exposed by this frontend.",
    readOnly: "READ + GATED TASK CREATION",
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
    health: "Coordination service health",
    healthOverall: "Provider-reported overall status",
    healthComponents: "Component status",
    healthReasons: "Actionable provider-reported reasons",
    healthNoComponents: "The provider returned no component health records.",
    healthNoReasons: "The provider reported no reasons for this component.",
    healthLastOperations: "Recent recorded operations",
    healthCheckedAt: "Health check time",
    healthLastWebhook: "Last webhook received",
    healthLastSyncSuccess: "Last successful GitHub sync",
    healthLastSyncAttempt: "Last GitHub sync attempt",
    healthLastTaskEvent: "Last task event",
    healthOnDemandNote: "On-demand status check — not continuous monitoring.",
    healthStatus: {
      healthy: "Healthy", degraded: "Degraded", stale: "Stale", failed: "Failed",
      unavailable: "Unavailable", not_configured: "Not configured", unknown: "Unknown",
    },
    healthField: "Agent health reported by provider",
    healthDetail: "Provider detail",
    traceOpen: "View task trace",
    traceClose: "Hide task trace",
    trace: "Task audit trace",
    traceSummary: "Lifecycle, delivery, and approval records returned by the coordination API.",
    traceNoEntries: "No lifecycle, delivery, or approval entries were returned.",
    traceEvents: "Lifecycle events",
    traceDeliveries: "Delivery attempts",
    traceApprovals: "Approval records",
    traceCorrelation: "Correlation",
    traceIdempotencyKey: "Idempotency key",
    traceEventId: "Source event ID",
    traceAttempts: "Task attempts",
    traceAgent: "Agent",
    traceAt: "Recorded at",
    traceKind: "Event kind",
    traceDetail: "Event detail",
    traceChannel: "Channel",
    traceQueue: "Queue",
    traceMessageId: "Message ID",
    traceDeliveryStatus: "Delivery status",
    traceAttempt: "Attempt",
    traceRequestedBy: "Requested by",
    traceDecidedBy: "Decided by",
    traceEmptyEvents: "No lifecycle events were returned.",
    traceEmptyDeliveries: "No delivery attempts were returned.",
    traceEmptyApprovals: "No approval records were returned.",
    taskIdempotencyKey: "Idempotency key",
  },
  ar: {
    eyebrow: "CICC / التنسيق",
    title: "تنسيق الوكلاء",
    intro: "عرض سجلات الوكلاء والمهام والمقاييس وأحداث الويب هوك من مزوّد التنسيق. لا يتاح إنشاء المهام إلا عند تفعيل بوابته على الخادم؛ ولا تعرض هذه الواجهة التوجيه أو غيره من تغييرات حالة المهام.",
    readOnly: "قراءة + إنشاء مقيّد",
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
    health: "صحة خدمة التنسيق",
    healthOverall: "الحالة العامة كما أبلغ عنها المزوّد",
    healthComponents: "حالة المكوّنات",
    healthReasons: "أسباب قابلة للإجراء كما أبلغ عنها المزوّد",
    healthNoComponents: "لم يُرجع المزوّد سجلات لصحة المكوّنات.",
    healthNoReasons: "لم يُبلغ المزوّد عن أسباب لهذا المكوّن.",
    healthLastOperations: "أحدث العمليات المسجّلة",
    healthCheckedAt: "وقت فحص الصحة",
    healthLastWebhook: "آخر ويب هوك مستلم",
    healthLastSyncSuccess: "آخر مزامنة GitHub ناجحة",
    healthLastSyncAttempt: "آخر محاولة مزامنة GitHub",
    healthLastTaskEvent: "آخر حدث مهمة",
    healthOnDemandNote: "فحص حالة عند الطلب — وليس مراقبة مستمرة.",
    healthStatus: {
      healthy: "سليم", degraded: "متدهور", stale: "قديم", failed: "فشل",
      unavailable: "غير متاح", not_configured: "غير مضبوط", unknown: "غير معروف",
    },
    healthField: "صحة الوكيل كما أبلغ عنها المزوّد",
    healthDetail: "تفاصيل المزوّد",
    traceOpen: "عرض أثر المهمة",
    traceClose: "إخفاء أثر المهمة",
    trace: "أثر تدقيق المهمة",
    traceSummary: "سجلات دورة الحياة والتسليم والموافقة التي أعادتها واجهة التنسيق.",
    traceNoEntries: "لم تُرجع الواجهة سجلات لدورة الحياة أو التسليم أو الموافقات.",
    traceEvents: "أحداث دورة الحياة",
    traceDeliveries: "محاولات التسليم",
    traceApprovals: "سجلات الموافقة",
    traceCorrelation: "الربط",
    traceIdempotencyKey: "مفتاح منع التكرار",
    traceEventId: "معرّف الحدث المصدر",
    traceAttempts: "محاولات المهمة",
    traceAgent: "الوكيل",
    traceAt: "وقت التسجيل",
    traceKind: "نوع الحدث",
    traceDetail: "تفاصيل الحدث",
    traceChannel: "القناة",
    traceQueue: "قائمة الانتظار",
    traceMessageId: "معرّف الرسالة",
    traceDeliveryStatus: "حالة التسليم",
    traceAttempt: "المحاولة",
    traceRequestedBy: "طلبها",
    traceDecidedBy: "حسمها",
    traceEmptyEvents: "لم تُرجع أحداث لدورة الحياة.",
    traceEmptyDeliveries: "لم تُرجع محاولات للتسليم.",
    traceEmptyApprovals: "لم تُرجع سجلات للموافقة.",
    taskIdempotencyKey: "مفتاح منع التكرار",
  },
  fa: {
    eyebrow: "CICC / هماهنگی",
    title: "هماهنگی عامل‌ها",
    intro: "نمای رکوردهای عامل‌ها، وظایف، معیارها و رویدادهای وب‌هوک از منبع هماهنگی. ایجاد وظیفه فقط با فعال‌بودن دروازهٔ سرور در دسترس است؛ این رابط مسیردهی یا دیگر تغییرهای وضعیت وظیفه را ارائه نمی‌کند.",
    readOnly: "خواندن + ایجاد محدود",
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
    health: "سلامت سرویس هماهنگی",
    healthOverall: "وضعیت کلی گزارش‌شده از منبع",
    healthComponents: "وضعیت مؤلفه‌ها",
    healthReasons: "دلایل قابل اقدام گزارش‌شده از منبع",
    healthNoComponents: "منبع رکوردی برای سلامت مؤلفه‌ها برنگرداند.",
    healthNoReasons: "منبع برای این مؤلفه دلیلی گزارش نکرد.",
    healthLastOperations: "آخرین عملیات ثبت‌شده",
    healthCheckedAt: "زمان بررسی سلامت",
    healthLastWebhook: "آخرین وب‌هوک دریافت‌شده",
    healthLastSyncSuccess: "آخرین همگام‌سازی موفق گیت‌هاب",
    healthLastSyncAttempt: "آخرین تلاش همگام‌سازی گیت‌هاب",
    healthLastTaskEvent: "آخرین رویداد وظیفه",
    healthOnDemandNote: "بررسی وضعیت هنگام درخواست — نه پایش پیوسته.",
    healthStatus: {
      healthy: "سالم", degraded: "مختل", stale: "کهنه", failed: "ناموفق",
      unavailable: "در دسترس نیست", not_configured: "پیکربندی نشده", unknown: "نامشخص",
    },
    healthField: "سلامت عامل، گزارش‌شده از منبع",
    healthDetail: "جزئیات منبع",
    traceOpen: "مشاهدهٔ رد وظیفه",
    traceClose: "پنهان‌کردن رد وظیفه",
    trace: "رد ممیزی وظیفه",
    traceSummary: "رکوردهای چرخهٔ عمر، تحویل و تأیید بازگشتی از API هماهنگی.",
    traceNoEntries: "رکوردی از چرخهٔ عمر، تحویل یا تأیید بازگشت داده نشد.",
    traceEvents: "رویدادهای چرخهٔ عمر",
    traceDeliveries: "تلاش‌های تحویل",
    traceApprovals: "رکوردهای تأیید",
    traceCorrelation: "هم‌بستگی",
    traceIdempotencyKey: "کلید جلوگیری از تکرار",
    traceEventId: "شناسهٔ رویداد مبدأ",
    traceAttempts: "تلاش‌های وظیفه",
    traceAgent: "عامل",
    traceAt: "زمان ثبت",
    traceKind: "نوع رویداد",
    traceDetail: "جزئیات رویداد",
    traceChannel: "کانال",
    traceQueue: "صف",
    traceMessageId: "شناسهٔ پیام",
    traceDeliveryStatus: "وضعیت تحویل",
    traceAttempt: "تلاش",
    traceRequestedBy: "درخواست‌کننده",
    traceDecidedBy: "تصمیم‌گیرنده",
    traceEmptyEvents: "رویدادی از چرخهٔ عمر بازگردانده نشد.",
    traceEmptyDeliveries: "تلاشی برای تحویل بازگردانده نشد.",
    traceEmptyApprovals: "رکوردی از تأیید بازگردانده نشد.",
    taskIdempotencyKey: "کلید جلوگیری از تکرار",
  },
};

const workflowCopy: Record<Locale, WorkflowMessages> = {
  en: {
    taskCreation: "Create a coordination task",
    taskCreationSummary: "Task creation uses a fixed server-side route and its explicit gate. The approved BFF policy is create-only: existing provider routing decisions are shown read-only. This frontend does not authenticate users.",
    taskCreationDisabled: "Task creation is disabled for this deployment. No task was submitted. Enable the server-side create gate only behind trusted single-tenant access controls.",
    taskKindLabel: "Task kind",
    taskTitleLabel: "Task title",
    taskPriorityLabel: "Priority (1–10)",
    taskPayloadLabel: "Task payload (JSON object)",
    taskPayloadHint: "Provide only fields accepted by your coordination policy. Routing rules may read labels or required capabilities.",
    taskPayloadInvalid: "Enter a valid JSON object for the task payload.",
    taskKindHint: "Use a kind supported by the configured coordination provider (lowercase letters, digits, and underscores).",
    taskRequiresApproval: "Require approval before work proceeds",
    taskCreateSubmit: "Create task",
    taskCreating: "Submitting task…",
    taskCreated: "The provider accepted the task creation request.",
    taskCreatedDuplicate: "The provider reported that this request matched an existing task.",
    taskCreatedState: "Provider-reported state",
    taskCreateError: "The server rejected the task request. Check the fields and the provider policy.",
    taskCreateUncertain: "The response could not confirm whether the task was created. Refresh the task list and trace before retrying to avoid duplicate work.",
    taskRouting: "Routing decision",
    taskRouteVia: "Routing method",
    taskRouteRule: "Matched rule",
    taskRouteScore: "Score",
    taskRouteCandidates: "Eligible candidates",
    taskRouteReasons: "Routing reasons",
    taskRoutingUnreported: "The provider has not returned a routing explanation.",
    taskResult: "Task result reported by provider",
    taskResultEmpty: "The provider returned an empty result.",
    taskProgress: "Reported progress",
    taskAttempts: "Attempts reported",
    pageNavigation: "Task result pages",
    pageSize: "Tasks per page",
    previousPage: "Previous page",
    nextPage: "Next page",
    page: "Page",
  },
  ar: {
    taskCreation: "إنشاء مهمة تنسيق",
    taskCreationSummary: "يستخدم إنشاء المهام مسارًا ثابتًا على الخادم وبوابة صريحة. سياسة BFF المعتمدة تقتصر على الإنشاء: تُعرض قرارات التوجيه الحالية من المزوّد للقراءة فقط. لا تصادق هذه الواجهة على المستخدمين.",
    taskCreationDisabled: "إنشاء المهام غير مفعّل لهذا النشر. لم تُرسل أي مهمة. لا تفعّل بوابة الإنشاء على الخادم إلا خلف ضوابط وصول موثوقة لمستأجر واحد.",
    taskKindLabel: "نوع المهمة",
    taskTitleLabel: "عنوان المهمة",
    taskPriorityLabel: "الأولوية (١–١٠)",
    taskPayloadLabel: "حمولة المهمة (كائن JSON)",
    taskPayloadHint: "أدخل الحقول التي تقبلها سياسة التنسيق فقط. قد تستخدم قواعد التوجيه التسميات أو الإمكانات المطلوبة.",
    taskPayloadInvalid: "أدخل كائن JSON صالحًا لحمولة المهمة.",
    taskKindHint: "استخدم نوعًا يدعمه مزوّد التنسيق المضبوط (أحرف لاتينية صغيرة وأرقام وشرطات سفلية).",
    taskRequiresApproval: "طلب موافقة قبل متابعة العمل",
    taskCreateSubmit: "إنشاء مهمة",
    taskCreating: "جارٍ إرسال المهمة…",
    taskCreated: "أكد المزوّد قبول طلب إنشاء المهمة.",
    taskCreatedDuplicate: "أفاد المزوّد بأن الطلب يطابق مهمة موجودة.",
    taskCreatedState: "الحالة كما أبلغ عنها المزوّد",
    taskCreateError: "رفض الخادم طلب المهمة. تحقّق من الحقول وسياسة المزوّد.",
    taskCreateUncertain: "لم تؤكد الاستجابة ما إذا أُنشئت المهمة. حدّث قائمة المهام وسجلّ التتبع قبل إعادة المحاولة لتجنّب العمل المكرر.",
    taskRouting: "قرار التوجيه",
    taskRouteVia: "طريقة التوجيه",
    taskRouteRule: "القاعدة المطابقة",
    taskRouteScore: "الدرجة",
    taskRouteCandidates: "المرشحون المؤهلون",
    taskRouteReasons: "أسباب التوجيه",
    taskRoutingUnreported: "لم يُرجع المزوّد تفسيرًا للتوجيه.",
    taskResult: "نتيجة المهمة كما أبلغ عنها المزوّد",
    taskResultEmpty: "أعاد المزوّد نتيجة فارغة.",
    taskProgress: "التقدم المبلّغ عنه",
    taskAttempts: "المحاولات المبلّغ عنها",
    pageNavigation: "صفحات نتائج المهام",
    pageSize: "المهام في الصفحة",
    previousPage: "الصفحة السابقة",
    nextPage: "الصفحة التالية",
    page: "الصفحة",
  },
  fa: {
    taskCreation: "ایجاد وظیفهٔ هماهنگی",
    taskCreationSummary: "ایجاد وظیفه از مسیر ثابت سمت‌سرور و دروازهٔ صریح استفاده می‌کند. سیاست تأییدشدهٔ BFF فقط ایجاد است: تصمیم‌های مسیریابی گزارش‌شده از منبع فقط‌خواندنی نمایش داده می‌شوند. این رابط کاربران را احراز هویت نمی‌کند.",
    taskCreationDisabled: "ایجاد وظیفه در این استقرار فعال نیست. هیچ وظیفه‌ای ارسال نشد. دروازهٔ ایجاد را فقط پشت کنترل دسترسی معتبر تک‌مستاجری فعال کنید.",
    taskKindLabel: "نوع وظیفه",
    taskTitleLabel: "عنوان وظیفه",
    taskPriorityLabel: "اولویت (۱–۱۰)",
    taskPayloadLabel: "بار وظیفه (شیء JSON)",
    taskPayloadHint: "فقط فیلدهای پذیرفته‌شده توسط سیاست هماهنگی را وارد کنید. قواعد مسیریابی ممکن است برچسب‌ها یا قابلیت‌های لازم را بخوانند.",
    taskPayloadInvalid: "برای بار وظیفه یک شیء JSON معتبر وارد کنید.",
    taskKindHint: "از نوعی پشتیبانی‌شده توسط ارائه‌دهندهٔ هماهنگی پیکربندی‌شده استفاده کنید (حروف کوچک لاتین، رقم و زیرخط).",
    taskRequiresApproval: "پیش از ادامهٔ کار نیازمند تأیید باشد",
    taskCreateSubmit: "ایجاد وظیفه",
    taskCreating: "در حال ارسال وظیفه…",
    taskCreated: "ارائه‌دهنده درخواست ایجاد وظیفه را پذیرفت.",
    taskCreatedDuplicate: "ارائه‌دهنده گزارش کرد این درخواست با وظیفه‌ای موجود تطبیق دارد.",
    taskCreatedState: "وضعیت گزارش‌شده از ارائه‌دهنده",
    taskCreateError: "سرور درخواست وظیفه را نپذیرفت. فیلدها و سیاست ارائه‌دهنده را بررسی کنید.",
    taskCreateUncertain: "پاسخ ایجاد وظیفه را تأیید نکرد. برای جلوگیری از کار تکراری، پیش از تلاش دوباره فهرست وظایف و ردگیری را تازه کنید.",
    taskRouting: "تصمیم مسیریابی",
    taskRouteVia: "روش مسیریابی",
    taskRouteRule: "قاعدهٔ منطبق",
    taskRouteScore: "امتیاز",
    taskRouteCandidates: "نامزدهای واجد شرایط",
    taskRouteReasons: "دلایل مسیریابی",
    taskRoutingUnreported: "ارائه‌دهنده توضیحی برای مسیریابی برنگردانده است.",
    taskResult: "نتیجهٔ وظیفه گزارش‌شده از ارائه‌دهنده",
    taskResultEmpty: "ارائه‌دهنده نتیجهٔ خالی برگرداند.",
    taskProgress: "پیشرفت گزارش‌شده",
    taskAttempts: "تلاش‌های گزارش‌شده",
    pageNavigation: "صفحه‌های نتایج وظیفه",
    pageSize: "وظیفه در هر صفحه",
    previousPage: "صفحهٔ قبل",
    nextPage: "صفحهٔ بعد",
    page: "صفحه",
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

function healthStatusLabel(status: CoordinationHealthStatus, messages: Messages): string {
  return messages.healthStatus[status];
}

function HealthContent({ data, locale, messages }: { data: CoordinationHealth; locale: Locale; messages: Messages }) {
  const operations = data.last_operations;
  const operationRows = [
    [messages.healthLastWebhook, operations.last_webhook_received],
    [messages.healthLastSyncSuccess, operations.last_github_sync_success],
    [messages.healthLastSyncAttempt, operations.last_github_sync_attempt],
    [messages.healthLastTaskEvent, operations.last_task_event],
  ] as const;

  return (
    <div className={styles.healthContent}>
      <div className={styles.healthSummary}>
        <div>
          <span className={styles.healthLabel}>{messages.healthOverall}</span>
          <strong className={styles.statusTag} data-health-status={data.overall}>
            {healthStatusLabel(data.overall, messages)}
          </strong>
        </div>
        <p>{messages.healthOnDemandNote} <bdi dir="auto">{operations.note}</bdi></p>
        {data.at && <time aria-label={messages.healthCheckedAt} dateTime={data.at}>{messages.healthCheckedAt}: {formatTimestamp(data.at, locale, messages.noTimestamp)}</time>}
      </div>

      <section className={styles.healthSection} aria-label={messages.healthComponents}>
        <h3>{messages.healthComponents}</h3>
        {data.components.length === 0 ? <p className={styles.inlineNote}>{messages.healthNoComponents}</p> : (
          <ul className={styles.healthList}>
            {data.components.map((component) => (
              <li key={component.key} className={styles.healthCard}>
                <div className={styles.cardHeading}>
                  <h4><bdi dir="ltr">{component.key}</bdi></h4>
                  <span className={styles.statusTag} data-health-status={component.status}>
                    {healthStatusLabel(component.status, messages)}
                  </span>
                </div>
                <p className={styles.healthDetail} dir="auto">{component.detail}</p>
                {component.reasons.length > 0 ? (
                  <ul className={styles.healthReasons} aria-label={messages.healthReasons}>
                    {component.reasons.map((reason, index) => <li key={`${component.key}-${index}`} dir="auto">{reason}</li>)}
                  </ul>
                ) : <p className={styles.inlineNote}>{messages.healthNoReasons}</p>}
              </li>
            ))}
          </ul>
        )}
        {data.reasons.length > 0 && (
          <div className={styles.overallReasons}>
            <h4>{messages.healthReasons}</h4>
            <ul>{data.reasons.map((reason, index) => <li key={`${index}-${reason}`} dir="auto">{reason}</li>)}</ul>
          </div>
        )}
      </section>

      <section className={styles.healthSection} aria-label={messages.healthLastOperations}>
        <h3>{messages.healthLastOperations}</h3>
        <dl className={styles.smallMeta}>
          {operationRows.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>{formatTimestamp(value, locale, messages.noTimestamp)}</dd>
            </div>
          ))}
        </dl>
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
              {agent.stale && <span className={`${styles.statusTag} ${styles.warningTag}`}>{messages.stale}</span>}
            </div>
          </div>
          <dl className={styles.smallMeta}>
            <div><dt>{messages.agentStatus}</dt><dd><bdi dir="auto">{agent.status}</bdi></dd></div>
            {agent.health && <div><dt>{messages.healthField}</dt><dd><bdi dir="ltr">{agent.health}</bdi></dd></div>}
            <div><dt>{messages.lastSeen}{agent.last_seen_field && <> · <code><bdi dir="ltr">{agent.last_seen_field}</bdi></code></>}</dt><dd>{formatTimestamp(agent.last_seen, locale, messages.noTimestamp)}</dd></div>
            <div><dt>{messages.activeTasks}</dt><dd>{formatNumber(agent.active_tasks, locale)}</dd></div>
            <div><dt>{messages.completedTasks}</dt><dd>{formatNumber(agent.completed_tasks, locale)}</dd></div>
            <div><dt>{messages.failedTasks}</dt><dd>{formatNumber(agent.failed_tasks, locale)}</dd></div>
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

function TaskTraceContent({
  data,
  locale,
  messages,
}: {
  data: CoordinationTaskTrace;
  locale: Locale;
  messages: Messages;
}) {
  const hasRecords = data.events.length + data.deliveries.length + data.approvals.length > 0;
  return (
    <div className={styles.traceContent}>
      <p className={styles.scopeNote}>{messages.traceSummary}</p>
      <dl className={styles.smallMeta}>
        <div><dt>{messages.taskId}</dt><dd><code><bdi dir="ltr">{data.task_id}</bdi></code></dd></div>
        <div><dt>{messages.state}</dt><dd><bdi dir="ltr">{data.state}</bdi></dd></div>
        <div><dt>{messages.traceAgent}</dt><dd>{data.agent ? <bdi dir="ltr">{data.agent}</bdi> : messages.noAgent}</dd></div>
        <div><dt>{messages.traceAttempts}</dt><dd>{formatNumber(data.attempts, locale)}</dd></div>
        {data.dead_letter && <div><dt>{messages.deadLetter}</dt><dd>{messages.deadLetter}</dd></div>}
        <div><dt>{messages.traceIdempotencyKey}</dt><dd>{data.correlation.idempotency_key ? <code><bdi dir="ltr">{data.correlation.idempotency_key}</bdi></code> : messages.noValue}</dd></div>
        <div><dt>{messages.traceEventId}</dt><dd>{data.correlation.event_id ? <code><bdi dir="ltr">{data.correlation.event_id}</bdi></code> : messages.noValue}</dd></div>
      </dl>
      {!hasRecords && <p className={styles.inlineNote}>{messages.traceNoEntries}</p>}

      <section className={styles.traceSection} aria-label={messages.traceEvents}>
        <h3>{messages.traceEvents}</h3>
        {data.events.length === 0 ? <p className={styles.inlineNote}>{messages.traceEmptyEvents}</p> : (
          <ol className={styles.traceList}>
            {data.events.map((event) => (
              <li key={event.id} className={styles.traceRecord}>
                <div className={styles.cardHeading}>
                  <h4><bdi dir="ltr">{event.kind}</bdi></h4>
                  <span className={styles.traceTime}>{formatTimestamp(event.at, locale, messages.noTimestamp)}</span>
                </div>
                {event.detail && <p className={styles.healthDetail} dir="auto">{event.detail}</p>}
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className={styles.traceSection} aria-label={messages.traceDeliveries}>
        <h3>{messages.traceDeliveries}</h3>
        {data.deliveries.length === 0 ? <p className={styles.inlineNote}>{messages.traceEmptyDeliveries}</p> : (
          <ol className={styles.traceList}>
            {data.deliveries.map((delivery) => (
              <li key={delivery.id} className={styles.traceRecord}>
                <div className={styles.cardHeading}>
                  <h4><bdi dir="ltr">{delivery.channel ?? messages.noValue}</bdi></h4>
                  {delivery.status && <span className={styles.statusTag}><bdi dir="ltr">{delivery.status}</bdi></span>}
                </div>
                <dl className={styles.smallMeta}>
                  <div><dt>{messages.traceQueue}</dt><dd>{delivery.queue ? <bdi dir="ltr">{delivery.queue}</bdi> : messages.noValue}</dd></div>
                  <div><dt>{messages.traceMessageId}</dt><dd>{delivery.message_id ? <code><bdi dir="ltr">{delivery.message_id}</bdi></code> : messages.noValue}</dd></div>
                  <div><dt>{messages.traceAttempt}</dt><dd>{formatNumber(delivery.attempt, locale)}</dd></div>
                  <div><dt>{messages.traceAt}</dt><dd>{formatTimestamp(delivery.at, locale, messages.noTimestamp)}</dd></div>
                </dl>
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className={styles.traceSection} aria-label={messages.traceApprovals}>
        <h3>{messages.traceApprovals}</h3>
        {data.approvals.length === 0 ? <p className={styles.inlineNote}>{messages.traceEmptyApprovals}</p> : (
          <ol className={styles.traceList}>
            {data.approvals.map((approval) => (
              <li key={approval.id} className={styles.traceRecord}>
                <div className={styles.cardHeading}>
                  <h4><bdi dir="ltr">{approval.status}</bdi></h4>
                  <span className={styles.traceTime}>{formatTimestamp(approval.at, locale, messages.noTimestamp)}</span>
                </div>
                <dl className={styles.smallMeta}>
                  <div><dt>{messages.traceRequestedBy}</dt><dd>{approval.requested_by ? <bdi dir="auto">{approval.requested_by}</bdi> : messages.noValue}</dd></div>
                  <div><dt>{messages.traceDecidedBy}</dt><dd>{approval.decided_by ? <bdi dir="auto">{approval.decided_by}</bdi> : messages.noValue}</dd></div>
                </dl>
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}

function TaskTracePanel({ taskId, locale, messages }: { taskId: string; locale: Locale; messages: Messages }) {
  const trace = useIntegrationResource(integrationEndpoints.coordinationTaskTrace(taskId), parseCoordinationTaskTrace);
  return (
    <ResourcePanel title={messages.trace} state={trace.state} onRefresh={trace.refresh}>
      {(data) => <TaskTraceContent data={data} locale={locale} messages={messages} />}
    </ResourcePanel>
  );
}

function TaskTraceDisclosure({ taskId, locale, messages }: { taskId: string; locale: Locale; messages: Messages }) {
  const [expanded, setExpanded] = useState(false);
  const panelId = useId().replaceAll(":", "");
  return (
    <div className={styles.traceDisclosure}>
      <button
        type="button"
        className={styles.traceButton}
        aria-expanded={expanded}
        aria-controls={panelId}
        onClick={() => setExpanded((value) => !value)}
      >
        {expanded ? messages.traceClose : messages.traceOpen}
      </button>
      <div id={panelId} hidden={!expanded}>
        {expanded && <TaskTracePanel taskId={taskId} locale={locale} messages={messages} />}
      </div>
    </div>
  );
}

function TaskCreationPanel({
  state,
  onRefresh,
  messages,
  kindOptions,
  onTaskCreated,
}: {
  state: ResourceState<CoordinationWriteCapabilities>;
  onRefresh: () => void;
  messages: Messages;
  kindOptions: string[];
  onTaskCreated: (result: CreateCoordinationTaskResult) => void;
}) {
  return (
    <ResourcePanel title={messages.taskCreation} state={state} onRefresh={onRefresh}>
      {(capabilities) => capabilities.task_creation_enabled ? (
        <TaskCreateForm messages={messages} kindOptions={kindOptions} onTaskCreated={onTaskCreated} />
      ) : (
        <div className={styles.taskCreateContent}>
          <p className={styles.scopeNote}>{messages.taskCreationSummary}</p>
          <p className={styles.inlineNote}>{messages.taskCreationDisabled}</p>
        </div>
      )}
    </ResourcePanel>
  );
}

function TaskCreateForm({
  messages,
  kindOptions,
  onTaskCreated,
}: {
  messages: Messages;
  kindOptions: string[];
  onTaskCreated: (result: CreateCoordinationTaskResult) => void;
}) {
  const id = useId().replaceAll(":", "");
  const [kind, setKind] = useState("");
  const [title, setTitle] = useState("");
  const [priority, setPriority] = useState("5");
  const [payload, setPayload] = useState("{}");
  const [requiresApproval, setRequiresApproval] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [payloadInvalid, setPayloadInvalid] = useState(false);
  const [failure, setFailure] = useState<IntegrationApiError | null>(null);
  const [created, setCreated] = useState<CreateCoordinationTaskResult | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFailure(null);
    setCreated(null);

    let decodedPayload: unknown;
    try {
      decodedPayload = JSON.parse(payload) as unknown;
    } catch {
      setPayloadInvalid(true);
      return;
    }
    if (typeof decodedPayload !== "object" || decodedPayload === null || Array.isArray(decodedPayload)) {
      setPayloadInvalid(true);
      return;
    }
    setPayloadInvalid(false);
    setSubmitting(true);
    try {
      const result = await createCoordinationTask({
        kind: kind.trim(),
        title: title.trim(),
        priority: Number(priority),
        payload: decodedPayload as Record<string, unknown>,
        requires_approval: requiresApproval,
      });
      setCreated(result);
      onTaskCreated(result);
    } catch (cause) {
      setFailure(cause instanceof IntegrationApiError ? cause : new IntegrationApiError("unavailable"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className={styles.taskCreateContent}>
      <p className={styles.scopeNote}>{messages.taskCreationSummary}</p>
      <form className={styles.taskForm} onSubmit={(event) => void submit(event)}>
        <label htmlFor={`${id}-kind`}>
          <span>{messages.taskKindLabel}</span>
          <input
            id={`${id}-kind`}
            type="text"
            dir="ltr"
            required
            minLength={1}
            maxLength={64}
            pattern="[a-z0-9_]{1,64}"
            list={`${id}-kind-options`}
            aria-describedby={`${id}-kind-hint`}
            value={kind}
            onChange={(event) => setKind(event.target.value)}
            autoComplete="off"
          />
        </label>
        <datalist id={`${id}-kind-options`}>
          {kindOptions.map((option) => <option key={option} value={option} />)}
        </datalist>
        <small id={`${id}-kind-hint`}>{messages.taskKindHint}</small>
        <label htmlFor={`${id}-title`}>
          <span>{messages.taskTitleLabel}</span>
          <input
            id={`${id}-title`}
            type="text"
            dir="auto"
            required
            maxLength={500}
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
        </label>
        <label htmlFor={`${id}-priority`}>
          <span>{messages.taskPriorityLabel}</span>
          <input
            id={`${id}-priority`}
            type="number"
            dir="ltr"
            min={1}
            max={10}
            step={1}
            required
            value={priority}
            onChange={(event) => setPriority(event.target.value)}
          />
        </label>
        <label htmlFor={`${id}-payload`}>
          <span>{messages.taskPayloadLabel}</span>
          <textarea
            id={`${id}-payload`}
            dir="ltr"
            rows={5}
            maxLength={64_000}
            spellCheck={false}
            aria-invalid={payloadInvalid}
            aria-describedby={`${id}-payload-hint${payloadInvalid ? ` ${id}-payload-error` : ""}`}
            value={payload}
            onChange={(event) => {
              setPayload(event.target.value);
              setPayloadInvalid(false);
            }}
          />
        </label>
        <small id={`${id}-payload-hint`}>{messages.taskPayloadHint}</small>
        {payloadInvalid && <span id={`${id}-payload-error`} className={styles.fieldError} role="alert">{messages.taskPayloadInvalid}</span>}
        <label className={styles.checkboxLabel} htmlFor={`${id}-approval`}>
          <input
            id={`${id}-approval`}
            type="checkbox"
            checked={requiresApproval}
            onChange={(event) => setRequiresApproval(event.target.checked)}
          />
          <span>{messages.taskRequiresApproval}</span>
        </label>
        <button className={styles.traceButton} type="submit" disabled={submitting}>
          {submitting ? messages.taskCreating : messages.taskCreateSubmit}
        </button>
      </form>
      {failure && (
        <p className={styles.errorNote} role="alert">
          {failure.kind === "unavailable" || failure.kind === "invalid_response"
            ? messages.taskCreateUncertain
            : messages.taskCreateError}
        </p>
      )}
      {created && (
        <div className={styles.taskCreateSuccess} role="status" aria-live="polite">
          <p>{messages.taskCreated}</p>
          {created.duplicate && <p>{messages.taskCreatedDuplicate}</p>}
          <dl className={styles.smallMeta}>
            <div><dt>{messages.taskId}</dt><dd><code><bdi dir="ltr">{created.task_id}</bdi></code></dd></div>
            <div><dt>{messages.kind}</dt><dd><bdi dir="ltr">{created.kind}</bdi></dd></div>
            <div><dt>{messages.taskCreatedState}</dt><dd><bdi dir="ltr">{created.state}</bdi></dd></div>
            <div><dt>{messages.taskIdempotencyKey}</dt><dd>{created.idempotency_key ? <code><bdi dir="ltr">{created.idempotency_key}</bdi></code> : messages.noValue}</dd></div>
          </dl>
        </div>
      )}
    </div>
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
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const id = useId().replaceAll(":", "");
  const normalizedQuery = query.trim().toLocaleLowerCase(locale);
  const filteredTasks = tasks.filter((task) => {
    if (stateFilter !== "ALL" && task.state !== stateFilter) return false;
    if (!normalizedQuery) return true;
    const searchable = [
      task.task_id,
      task.title,
      task.kind,
      task.state,
      task.agent,
      task.repo,
      task.branch_ref,
      task.result,
      task.routing_explanation?.via,
      task.routing_explanation?.rule,
      ...(task.routing_explanation?.reasons ?? []),
    ];
    return searchable.some((value) => value?.toLocaleLowerCase(locale).includes(normalizedQuery));
  });
  const pageCount = Math.max(1, Math.ceil(filteredTasks.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const visibleTasks = filteredTasks.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  const rangeStart = filteredTasks.length === 0 ? 0 : currentPage * pageSize + 1;
  const rangeEnd = Math.min((currentPage + 1) * pageSize, filteredTasks.length);

  return (
    <div>
      <div className={styles.filterBar}>
        <label htmlFor={`${id}-state`}>
          <span>{messages.filterState}</span>
          <select
            id={`${id}-state`}
            dir="ltr"
            value={stateFilter}
            onChange={(event) => {
              setStateFilter(event.target.value);
              setPage(0);
            }}
          >
            <option value="ALL">{messages.allStates}</option>
            {taskStates.map((state) => <option key={state} value={state}>{state}</option>)}
          </select>
        </label>
        <label htmlFor={`${id}-query`}>
          <span>{messages.searchLoaded}</span>
          <input
            id={`${id}-query`}
            dir="auto"
            type="search"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(0);
            }}
          />
        </label>
      </div>
      <p className={styles.scopeNote}>
        {messages.loadedScope} <bdi dir="ltr">{formatNumber(filteredTasks.length, locale)} / {formatNumber(tasks.length, locale)}</bdi> {messages.taskRecords}
      </p>
      {filteredTasks.length === 0 ? <p className={styles.inlineNote}>{messages.noMatches}</p> : (
        <>
          <nav className={styles.pageControls} aria-label={messages.pageNavigation}>
            <label htmlFor={`${id}-page-size`}>
              <span>{messages.pageSize}</span>
              <select
                id={`${id}-page-size`}
                dir="ltr"
                value={pageSize}
                onChange={(event) => {
                  setPageSize(Number(event.target.value));
                  setPage(0);
                }}
              >
                {[10, 25, 50].map((size) => <option key={size} value={size}>{formatNumber(size, locale)}</option>)}
              </select>
            </label>
            <span className={styles.pageIndicator} aria-live="polite">
              {messages.page} <bdi dir="ltr">{formatNumber(currentPage + 1, locale)} / {formatNumber(pageCount, locale)}</bdi>
              <span className={styles.pageRange}><bdi dir="ltr">{formatNumber(rangeStart, locale)}–{formatNumber(rangeEnd, locale)} / {formatNumber(filteredTasks.length, locale)}</bdi></span>
            </span>
            <div className={styles.pageButtons}>
              <button type="button" className={styles.traceButton} disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>
                {messages.previousPage}
              </button>
              <button type="button" className={styles.traceButton} disabled={currentPage >= pageCount - 1} onClick={() => setPage(currentPage + 1)}>
                {messages.nextPage}
              </button>
            </div>
          </nav>
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
                    {task.attempts !== null && <div><dt>{messages.taskAttempts}</dt><dd>{formatNumber(task.attempts, locale)}</dd></div>}
                    <div><dt>{messages.taskIdempotencyKey}</dt><dd>{task.idempotency_key ? <code><bdi dir="ltr">{task.idempotency_key}</bdi></code> : messages.noValue}</dd></div>
                  </dl>
                  {task.progress !== null && (
                    <div className={styles.taskProgress}>
                      <div><span>{messages.taskProgress}</span><bdi dir="ltr">{formatNumber(task.progress, locale)}%</bdi></div>
                      <progress aria-label={messages.taskProgress} aria-valuetext={`${formatNumber(task.progress, locale)}%`} value={task.progress} max={100} />
                    </div>
                  )}
                  <section className={styles.taskDetailSection} aria-label={messages.taskRouting}>
                    <h3>{messages.taskRouting}</h3>
                    {task.routing_explanation ? (
                      <>
                        <dl className={styles.smallMeta}>
                          <div><dt>{messages.taskRouteVia}</dt><dd><bdi dir="ltr">{task.routing_explanation.via}</bdi></dd></div>
                          {task.routing_explanation.rule && <div><dt>{messages.taskRouteRule}</dt><dd><bdi dir="auto">{task.routing_explanation.rule}</bdi></dd></div>}
                          {task.routing_explanation.score !== null && <div><dt>{messages.taskRouteScore}</dt><dd>{formatNumber(task.routing_explanation.score, locale)}</dd></div>}
                          {task.routing_explanation.candidates !== null && <div><dt>{messages.taskRouteCandidates}</dt><dd>{formatNumber(task.routing_explanation.candidates, locale)}</dd></div>}
                        </dl>
                        {task.routing_explanation.reasons.length > 0 && (
                          <ul className={styles.healthReasons}>
                            {task.routing_explanation.reasons.map((reason, index) => <li key={`${index}-${reason}`} dir="auto">{reason}</li>)}
                          </ul>
                        )}
                      </>
                    ) : <p className={styles.inlineNote}>{messages.taskRoutingUnreported}</p>}
                  </section>
                  {task.result !== null && (
                    <section className={styles.taskDetailSection} aria-label={messages.taskResult}>
                      <h3>{messages.taskResult}</h3>
                      <pre className={styles.taskResult} dir="auto">{task.result || messages.taskResultEmpty}</pre>
                    </section>
                  )}
                  <TaskTraceDisclosure taskId={task.task_id} locale={locale} messages={messages} />
                </details>
              </li>
            ))}
          </ul>
        </>
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
  const text: Messages = { ...copy[locale], ...workflowCopy[locale] };
  const id = useId().replaceAll(":", "");
  const [taskListKey, setTaskListKey] = useState(0);
  const health = useIntegrationResource(integrationEndpoints.coordinationHealth, parseCoordinationHealth);
  const metrics = useIntegrationResource(integrationEndpoints.coordinationMetrics, parseCoordinationMetrics);
  const agents = useIntegrationResource(integrationEndpoints.coordinationAgents, parseCoordinationAgents);
  const tasks = useIntegrationResource(integrationEndpoints.coordinationTasks, parseCoordinationTasks);
  const events = useIntegrationResource(integrationEndpoints.coordinationEvents, parseCoordinationEvents);
  const writeCapabilities = useIntegrationResource(
    integrationEndpoints.coordinationWriteCapabilities,
    parseCoordinationWriteCapabilities,
  );
  const taskKindOptions = Object.keys(metrics.state.data?.by_kind ?? {}).sort();

  function refreshCoordinationData() {
    tasks.refresh();
    metrics.refresh();
    agents.refresh();
    health.refresh();
  }

  function handleTaskCreated(result: CreateCoordinationTaskResult) {
    if (result.task_id) setTaskListKey((value) => value + 1);
    refreshCoordinationData();
  }

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
        <div className={styles.widePanel}>
          <ResourcePanel title={text.health} state={health.state} onRefresh={health.refresh}>
            {(data) => <HealthContent data={data} locale={locale} messages={text} />}
          </ResourcePanel>
        </div>

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
          <TaskCreationPanel
            state={writeCapabilities.state}
            onRefresh={writeCapabilities.refresh}
            messages={text}
            kindOptions={taskKindOptions}
            onTaskCreated={handleTaskCreated}
          />
        </div>

        <div className={styles.widePanel}>
          <ResourcePanel
            title={text.tasks}
            state={tasks.state}
            onRefresh={tasks.refresh}
            isEmpty={(data) => data.tasks.length === 0}
            emptyMessage={text.emptyTasks}
          >
            {(data) => (
              <TaskContent
                key={taskListKey}
                tasks={data.tasks}
                locale={locale}
                messages={text}
              />
            )}
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
