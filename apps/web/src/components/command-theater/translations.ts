import type {
  ConfidenceBasis,
  IntelligenceEntityType,
  IntelligenceRelationshipType,
  Locale,
  VerificationStatus,
} from "./types";

export type TheaterMessages = {
  eyebrow: string;
  title: string;
  subtitle: string;
  demoBadge: string;
  demoDescription: string;
  backendBadge: string;
  backendDescription: string;
  entitiesCount: string;
  relationshipsCount: string;
  sampleEntitiesCount: string;
  sampleRelationshipsCount: string;
  stageTitle: string;
  viewMode: string;
  view2d: string;
  view3d: string;
  mapLabel: string;
  mapDescription: string;
  mapLimitNotice: string;
  mapNodeLimitNotice: string;
  sceneLimitNotice: string;
  relationshipCountStatus: string;
  relationshipLoadedStatus: string;
  showMoreRelationships: string;
  loadMoreGraph: string;
  loadingMoreGraph: string;
  explorerTitle: string;
  entitiesTitle: string;
  entityCountStatus: string;
  entityLoadedStatus: string;
  showMoreEntities: string;
  relationshipsTitle: string;
  selectedEntity: string;
  investigationNavigation: string;
  previousEntity: string;
  nextEntity: string;
  investigationPosition: string;
  entityType: string;
  confidence: string;
  verificationStatusLabel: string;
  confidenceBasis: Record<ConfidenceBasis, string>;
  verificationStatuses: Record<VerificationStatus, string>;
  evidenceStatuses: Record<"verified" | "unverified", string>;
  evidence: string;
  noEvidence: string;
  demoNoEvidence: string;
  provenance: string;
  provenanceUnavailable: string;
  sourceRecordId: string;
  collectedAt: string;
  publishedAt: string;
  keyboardHelp: string;
  graphicsChecking: string;
  graphicsReady: string;
  graphicsUnavailable: string;
  graphicsContextLost: string;
  loading3d: string;
  canvasFallback: string;
  canvasLostFallback: string;
  switchTo2d: string;
  language: string;
  recordMetadata: string;
  loadingGraph: string;
  unconfiguredData: string;
  graphLoadError: string;
  invalidGraphData: string;
  emptyGraph: string;
  emptyGraphPage: string;
  retry: string;
  filterSearch: string;
  filterEntityType: string;
  filterRelationshipType: string;
  allEntityTypes: string;
  allRelationshipTypes: string;
  applyFilters: string;
  clearFilters: string;
  entityTypes: Record<IntelligenceEntityType, string>;
  relationshipTypes: Record<IntelligenceRelationshipType, string>;
};

const messages: Record<Locale, TheaterMessages> = {
  en: {
    eyebrow: "CICC / COMMAND THEATER",
    title: "Intelligence Command Theater",
    subtitle: "Explore relationships in an interactive 3D view or accessible 2D map.",
    demoBadge: "SYNTHETIC DEMO",
    demoDescription: "Synthetic sample only · no live feeds or verified evidence connected.",
    backendBadge: "CONFIGURED DATA SOURCE",
    backendDescription: "Records come from the configured provider. Verification, evidence, and provenance are record-specific; confidence is an assessment, not a fact.",
    entitiesCount: "Entities loaded",
    relationshipsCount: "Relationships loaded",
    sampleEntitiesCount: "Sample entities",
    sampleRelationshipsCount: "Sample relationships",
    stageTitle: "Relationship theater",
    viewMode: "Visualization mode",
    view2d: "2D map",
    view3d: "3D theater",
    mapLabel: "2D intelligence relationship map",
    mapDescription: "A visual overview of entities and relationships in the current graph.",
    mapLimitNotice: "Map shows {shown} of {total} relationships; use the explorer for the full list.",
    mapNodeLimitNotice: "Map shows {shown} of {total} entities; the explorer contains the full loaded set.",
    sceneLimitNotice: "3D renders {shownNodes} of {totalNodes} entities and {shownRelationships} of {totalRelationships} relationships at a time; use the explorer to inspect loaded records.",
    relationshipCountStatus: "Showing {shown} of {total} relationships.",
    relationshipLoadedStatus: "Showing {shown} of {loaded} loaded relationships; more may be available.",
    showMoreRelationships: "Show more relationships",
    loadMoreGraph: "Load more graph records",
    loadingMoreGraph: "Loading more records…",
    explorerTitle: "Intelligence graph explorer",
    entitiesTitle: "Entities",
    entityCountStatus: "Showing {shown} of {total} entities.",
    entityLoadedStatus: "Showing {shown} of {loaded} loaded entities; more may be available.",
    showMoreEntities: "Show more entities",
    relationshipsTitle: "Relationships",
    selectedEntity: "Selected entity",
    investigationNavigation: "Investigation history",
    previousEntity: "Previous entity in investigation",
    nextEntity: "Next entity in investigation",
    investigationPosition: "Step {current} of {total}.",
    entityType: "Entity type",
    confidence: "Confidence",
    verificationStatusLabel: "Verification status",
    confidenceBasis: {
      illustrative: "illustrative only",
      "analyst-assessed": "analyst assessment; not factual certainty",
      "model-assessed": "model assessment; not factual certainty",
      unavailable: "not provided",
    },
    verificationStatuses: {
      verified: "Verified",
      unverified: "Unverified",
      inferred: "Inferred",
      illustrative: "Illustrative only",
      unknown: "Unknown",
    },
    evidenceStatuses: { verified: "verified evidence", unverified: "unverified reference" },
    evidence: "Evidence",
    noEvidence: "No evidence references supplied by the configured source.",
    demoNoEvidence: "No evidence attached to this synthetic sample.",
    provenance: "Provenance",
    provenanceUnavailable: "No provenance supplied.",
    sourceRecordId: "Source record ID",
    collectedAt: "Collected",
    publishedAt: "Published",
    keyboardHelp: "Use the arrow keys to move between related entities. Home and End move to the first and last entity.",
    graphicsChecking: "Checking graphics support…",
    graphicsReady: "WebGL is available. The 3D scene loads only when selected.",
    graphicsUnavailable: "3D is unavailable in this browser. The 2D map and graph explorer remain available.",
    graphicsContextLost: "The WebGL context was lost. Continue in 2D; the 3D view is unavailable.",
    loading3d: "Loading the 3D theater…",
    canvasFallback: "A WebGL context could not be created. Continue with the 2D relationship map.",
    canvasLostFallback: "The WebGL context was lost. Continue with the 2D relationship map.",
    switchTo2d: "Switch to 2D map",
    language: "Interface language",
    recordMetadata: "Record metadata",
    loadingGraph: "Loading graph records…",
    unconfiguredData: "No graph data source is configured. Synthetic data will not be substituted.",
    graphLoadError: "The configured data source could not be reached. No synthetic data was substituted.",
    invalidGraphData: "The data source returned an invalid graph response. No synthetic data was substituted.",
    emptyGraph: "The configured data source returned no graph records for these filters.",
    emptyGraphPage: "This page contains no graph records; load the next page to continue.",
    retry: "Retry",
    filterSearch: "Search entities and relationships",
    filterEntityType: "Entity type filter",
    filterRelationshipType: "Relationship type filter",
    allEntityTypes: "All entity types",
    allRelationshipTypes: "All relationship types",
    applyFilters: "Apply filters",
    clearFilters: "Clear filters",
    entityTypes: {
      "threat-actor": "Threat actor",
      campaign: "Campaign",
      domain: "Domain",
      incident: "Incident",
      asset: "Asset",
    },
    relationshipTypes: {
      "associated-with": "associated with",
      uses: "uses",
      "observed-in": "observed in",
      affects: "affects",
    },
  },
  ar: {
    eyebrow: "CICC / مسرح القيادة",
    title: "مسرح قيادة الاستخبارات",
    subtitle: "استكشف العلاقات في عرض ثلاثي الأبعاد تفاعلي أو خريطة ثنائية الأبعاد سهلة الوصول.",
    demoBadge: "بيانات اصطناعية للعرض",
    demoDescription: "عينة اصطناعية فقط · لا توجد مصادر مباشرة أو أدلة موثقة متصلة.",
    backendBadge: "مصدر بيانات مهيأ",
    backendDescription: "السجلات من موفر CICC المهيأ. حالة التحقق والأدلة والمنشأ خاصة بكل سجل؛ درجة الثقة تقدير وليست حقيقة.",
    entitiesCount: "الكيانات المحمّلة",
    relationshipsCount: "العلاقات المحمّلة",
    sampleEntitiesCount: "كيانات العينة",
    sampleRelationshipsCount: "علاقات العينة",
    stageTitle: "مسرح العلاقات",
    viewMode: "نمط العرض",
    view2d: "خريطة ثنائية الأبعاد",
    view3d: "مسرح ثلاثي الأبعاد",
    mapLabel: "خريطة العلاقات الاستخباراتية ثنائية الأبعاد",
    mapDescription: "عرض مرئي للكيانات والعلاقات في الرسم الحالي.",
    mapLimitNotice: "تعرض الخريطة {shown} من أصل {total} علاقة؛ استخدم المستكشف للاطلاع على القائمة كاملة.",
    mapNodeLimitNotice: "تعرض الخريطة {shown} من أصل {total} كيانًا؛ يعرض المستكشف المجموعة المحمّلة كاملة.",
    sceneLimitNotice: "يعرض المشهد ثلاثي الأبعاد {shownNodes} من أصل {totalNodes} كيانًا و{shownRelationships} من أصل {totalRelationships} علاقة في كل مرة؛ استخدم المستكشف لفحص السجلات المحمّلة.",
    relationshipCountStatus: "يُعرض {shown} من أصل {total} علاقة.",
    relationshipLoadedStatus: "يُعرض {shown} من أصل {loaded} علاقة محمّلة؛ قد تتوفر المزيد.",
    showMoreRelationships: "عرض المزيد من العلاقات",
    loadMoreGraph: "تحميل المزيد من سجلات الرسم",
    loadingMoreGraph: "جارٍ تحميل سجلات إضافية…",
    explorerTitle: "مستكشف الرسم الاستخباراتي",
    entitiesTitle: "الكيانات",
    entityCountStatus: "يُعرض {shown} من أصل {total} كيان.",
    entityLoadedStatus: "يُعرض {shown} من أصل {loaded} كيان محمّل؛ قد تتوفر المزيد.",
    showMoreEntities: "عرض المزيد من الكيانات",
    relationshipsTitle: "العلاقات",
    selectedEntity: "الكيان المحدد",
    investigationNavigation: "سجل التنقل في التحقيق",
    previousEntity: "الكيان السابق في التحقيق",
    nextEntity: "الكيان التالي في التحقيق",
    investigationPosition: "الخطوة {current} من {total}.",
    entityType: "نوع الكيان",
    confidence: "درجة الثقة",
    verificationStatusLabel: "حالة التحقق",
    confidenceBasis: {
      illustrative: "توضيحية فقط",
      "analyst-assessed": "تقدير محلل، وليس حقيقة مؤكدة",
      "model-assessed": "تقدير آلي، وليس حقيقة مؤكدة",
      unavailable: "غير متاحة",
    },
    verificationStatuses: {
      verified: "متحقق منه",
      unverified: "غير متحقق منه",
      inferred: "استدلالي",
      illustrative: "توضيحي فقط",
      unknown: "غير معروف",
    },
    evidenceStatuses: { verified: "دليل متحقق منه", unverified: "مرجع غير متحقق منه" },
    evidence: "الأدلة",
    noEvidence: "لم يقدّم مصدر البيانات المهيأ أي مراجع أدلة.",
    demoNoEvidence: "لا توجد أدلة مرفقة بهذه العينة الاصطناعية.",
    provenance: "المنشأ",
    provenanceUnavailable: "لم تُقدّم معلومات عن المنشأ.",
    sourceRecordId: "معرّف سجل المصدر",
    collectedAt: "وقت الجمع",
    publishedAt: "وقت النشر",
    keyboardHelp: "استخدم مفاتيح الأسهم للتنقل بين الكيانات المرتبطة. ينقلك مفتاحا Home وEnd إلى أول كيان وآخره.",
    graphicsChecking: "جارٍ التحقق من دعم الرسومات…",
    graphicsReady: "WebGL متاح. لن يُحمّل المشهد ثلاثي الأبعاد إلا عند اختياره.",
    graphicsUnavailable: "العرض ثلاثي الأبعاد غير متاح في هذا المتصفح. تظل الخريطة ومستكشف العلاقات متاحين.",
    graphicsContextLost: "فُقد سياق WebGL. تابع باستخدام العرض ثنائي الأبعاد؛ العرض ثلاثي الأبعاد غير متاح.",
    loading3d: "جارٍ تحميل المسرح ثلاثي الأبعاد…",
    canvasFallback: "تعذّر إنشاء سياق WebGL. يمكنك المتابعة باستخدام خريطة العلاقات ثنائية الأبعاد.",
    canvasLostFallback: "فُقد سياق WebGL. يمكنك المتابعة باستخدام خريطة العلاقات ثنائية الأبعاد.",
    switchTo2d: "الانتقال إلى الخريطة ثنائية الأبعاد",
    language: "لغة الواجهة",
    recordMetadata: "بيانات السجل الوصفية",
    loadingGraph: "جارٍ تحميل سجلات الرسم…",
    unconfiguredData: "لم يتم إعداد مصدر بيانات للرسم. لن تُستبدل البيانات الاصطناعية به.",
    graphLoadError: "تعذر الوصول إلى مصدر البيانات المهيأ. لم تُستخدم بيانات اصطناعية بديلة.",
    invalidGraphData: "أعاد مصدر البيانات رسمًا بيانيًا غير صالح. لم تُستخدم بيانات اصطناعية بديلة.",
    emptyGraph: "لم يُرجع مصدر البيانات سجلات لهذا الرسم أو لهذه المرشحات.",
    emptyGraphPage: "لا تحتوي هذه الصفحة على سجلات للرسم؛ حمّل الصفحة التالية للمتابعة.",
    retry: "إعادة المحاولة",
    filterSearch: "البحث في الكيانات والعلاقات",
    filterEntityType: "تصفية نوع الكيان",
    filterRelationshipType: "تصفية نوع العلاقة",
    allEntityTypes: "كل أنواع الكيانات",
    allRelationshipTypes: "كل أنواع العلاقات",
    applyFilters: "تطبيق المرشحات",
    clearFilters: "مسح المرشحات",
    entityTypes: {
      "threat-actor": "جهة تهديد",
      campaign: "حملة",
      domain: "نطاق",
      incident: "حادثة",
      asset: "أصل تقني",
    },
    relationshipTypes: {
      "associated-with": "مرتبط بـ",
      uses: "يستخدم",
      "observed-in": "رُصد في",
      affects: "يؤثر في",
    },
  },
  fa: {
    eyebrow: "CICC / مرکز فرماندهی",
    title: "تالار فرماندهی اطلاعات",
    subtitle: "پیوندها را در نمای سه‌بعدی تعاملی یا نقشهٔ دوبعدی دسترس‌پذیر بررسی کنید.",
    demoBadge: "دادهٔ نمایشی ساختگی",
    demoDescription: "فقط نمونهٔ ساختگی · هیچ خوراک زنده یا مدرک تأییدشده‌ای متصل نیست.",
    backendBadge: "منبع دادهٔ پیکربندی‌شده",
    backendDescription: "رکوردها از فراهم‌کنندهٔ پیکربندی‌شدهٔ CICC هستند. وضعیت تأیید، مدرک و منشأ برای هر رکورد جداست؛ میزان اطمینان ارزیابی است، نه حقیقت.",
    entitiesCount: "موجودیت‌های بارگیری‌شده",
    relationshipsCount: "پیوندهای بارگیری‌شده",
    sampleEntitiesCount: "موجودیت‌های نمونه",
    sampleRelationshipsCount: "پیوندهای نمونه",
    stageTitle: "تالار پیوندها",
    viewMode: "حالت نمایش",
    view2d: "نقشهٔ دوبعدی",
    view3d: "تالار سه‌بعدی",
    mapLabel: "نقشهٔ دوبعدی پیوندهای اطلاعاتی",
    mapDescription: "نمایی بصری از موجودیت‌ها و پیوندهای گراف کنونی.",
    mapLimitNotice: "نقشه {shown} مورد از {total} پیوند را نشان می‌دهد؛ برای فهرست کامل از کاوشگر استفاده کنید.",
    mapNodeLimitNotice: "نقشه {shown} مورد از {total} موجودیت را نشان می‌دهد؛ کاوشگر همهٔ موارد بارگیری‌شده را دارد.",
    sceneLimitNotice: "نمای سه‌بعدی هم‌زمان {shownNodes} از {totalNodes} موجودیت و {shownRelationships} از {totalRelationships} پیوند را نمایش می‌دهد؛ برای بررسی رکوردهای بارگیری‌شده از کاوشگر استفاده کنید.",
    relationshipCountStatus: "نمایش {shown} از {total} پیوند.",
    relationshipLoadedStatus: "نمایش {shown} از {loaded} پیوند بارگیری‌شده؛ ممکن است موارد بیشتری باشد.",
    showMoreRelationships: "نمایش پیوندهای بیشتر",
    loadMoreGraph: "بارگیری رکوردهای بیشتر گراف",
    loadingMoreGraph: "در حال بارگیری رکوردهای بیشتر…",
    explorerTitle: "کاوشگر گراف اطلاعاتی",
    entitiesTitle: "موجودیت‌ها",
    entityCountStatus: "نمایش {shown} از {total} موجودیت.",
    entityLoadedStatus: "نمایش {shown} از {loaded} موجودیت بارگیری‌شده؛ ممکن است موارد بیشتری باشد.",
    showMoreEntities: "نمایش موجودیت‌های بیشتر",
    relationshipsTitle: "پیوندها",
    selectedEntity: "موجودیت انتخاب‌شده",
    investigationNavigation: "تاریخچهٔ بررسی",
    previousEntity: "موجودیت پیشین در بررسی",
    nextEntity: "موجودیت بعدی در بررسی",
    investigationPosition: "گام {current} از {total}.",
    entityType: "نوع موجودیت",
    confidence: "میزان اطمینان",
    verificationStatusLabel: "وضعیت تأیید",
    confidenceBasis: {
      illustrative: "صرفاً نمایشی",
      "analyst-assessed": "ارزیابی تحلیل‌گر؛ نه حقیقت قطعی",
      "model-assessed": "ارزیابی مدل؛ نه حقیقت قطعی",
      unavailable: "ارائه نشده",
    },
    verificationStatuses: {
      verified: "تأییدشده",
      unverified: "تأییدنشده",
      inferred: "استنباطی",
      illustrative: "صرفاً نمایشی",
      unknown: "نامشخص",
    },
    evidenceStatuses: { verified: "مدرک تأییدشده", unverified: "مرجع تأییدنشده" },
    evidence: "مدرک",
    noEvidence: "منبع دادهٔ پیکربندی‌شده هیچ مرجع مدرکی ارائه نکرده است.",
    demoNoEvidence: "برای این نمونهٔ ساختگی مدرکی پیوست نشده است.",
    provenance: "منشأ",
    provenanceUnavailable: "اطلاعات منشأ ارائه نشده است.",
    sourceRecordId: "شناسهٔ رکورد منبع",
    collectedAt: "زمان گردآوری",
    publishedAt: "زمان انتشار",
    keyboardHelp: "با کلیدهای جهت‌نما میان موجودیت‌های مرتبط جابه‌جا شوید. کلیدهای Home و End به ابتدا و انتها می‌روند.",
    graphicsChecking: "در حال بررسی پشتیبانی گرافیکی…",
    graphicsReady: "WebGL در دسترس است. صحنهٔ سه‌بعدی فقط هنگام انتخاب بارگیری می‌شود.",
    graphicsUnavailable: "نمای سه‌بعدی در این مرورگر در دسترس نیست. نقشه و کاوشگر پیوندها همچنان قابل استفاده‌اند.",
    graphicsContextLost: "زمینهٔ WebGL از دست رفت. با نمای دوبعدی ادامه دهید؛ نمای سه‌بعدی در دسترس نیست.",
    loading3d: "در حال بارگیری تالار سه‌بعدی…",
    canvasFallback: "ایجاد زمینهٔ WebGL ممکن نشد. از نقشهٔ دوبعدی پیوندها استفاده کنید.",
    canvasLostFallback: "زمینهٔ WebGL از دست رفت. از نقشهٔ دوبعدی پیوندها استفاده کنید.",
    switchTo2d: "رفتن به نقشهٔ دوبعدی",
    language: "زبان رابط کاربری",
    recordMetadata: "فرادادهٔ رکورد",
    loadingGraph: "در حال بارگیری رکوردهای گراف…",
    unconfiguredData: "منبع داده‌ای برای گراف پیکربندی نشده است. دادهٔ ساختگی جایگزین نخواهد شد.",
    graphLoadError: "دسترسی به منبع دادهٔ پیکربندی‌شده ممکن نشد. دادهٔ ساختگی جایگزین نشد.",
    invalidGraphData: "منبع داده پاسخ گراف نامعتبر برگرداند. دادهٔ ساختگی جایگزین نشد.",
    emptyGraph: "منبع داده برای گراف یا پالایه‌های کنونی رکوردی برنگرداند.",
    emptyGraphPage: "این صفحه رکورد گرافی ندارد؛ برای ادامه صفحهٔ بعد را بارگیری کنید.",
    retry: "تلاش دوباره",
    filterSearch: "جست‌وجو در موجودیت‌ها و پیوندها",
    filterEntityType: "پالایهٔ نوع موجودیت",
    filterRelationshipType: "پالایهٔ نوع پیوند",
    allEntityTypes: "همهٔ نوع‌های موجودیت",
    allRelationshipTypes: "همهٔ نوع‌های پیوند",
    applyFilters: "اعمال پالایه‌ها",
    clearFilters: "پاک‌کردن پالایه‌ها",
    entityTypes: {
      "threat-actor": "عامل تهدید",
      campaign: "کارزار",
      domain: "دامنه",
      incident: "رخداد",
      asset: "دارایی",
    },
    relationshipTypes: {
      "associated-with": "مرتبط با",
      uses: "استفاده می‌کند از",
      "observed-in": "مشاهده‌شده در",
      affects: "تأثیرگذار بر",
    },
  },
};

export function getMessages(locale: Locale): TheaterMessages {
  return messages[locale];
}
