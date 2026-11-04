import type {
  IntelligenceEntityType,
  IntelligenceRelationshipType,
  Locale,
} from "./types";

export type TheaterMessages = {
  eyebrow: string;
  title: string;
  subtitle: string;
  demoBadge: string;
  demoDescription: string;
  entitiesCount: string;
  relationshipsCount: string;
  stageTitle: string;
  viewMode: string;
  view2d: string;
  view3d: string;
  mapLabel: string;
  mapDescription: string;
  mapLimitNotice: string;
  relationshipCountStatus: string;
  showMoreRelationships: string;
  explorerTitle: string;
  entitiesTitle: string;
  relationshipsTitle: string;
  selectedEntity: string;
  entityType: string;
  confidence: string;
  illustrative: string;
  evidence: string;
  noEvidence: string;
  provenance: string;
  keyboardHelp: string;
  graphicsChecking: string;
  graphicsReady: string;
  graphicsUnavailable: string;
  loading3d: string;
  canvasFallback: string;
  switchTo2d: string;
  language: string;
  sampleSource: string;
  entityTypes: Record<IntelligenceEntityType, string>;
  relationshipTypes: Record<IntelligenceRelationshipType, string>;
};

const messages: Record<Locale, TheaterMessages> = {
  en: {
    eyebrow: "CICC / COMMAND THEATER",
    title: "Intelligence Command Theater",
    subtitle: "Explore relationships in an interactive 3D view or accessible 2D map.",
    demoBadge: "DEMO DATA",
    demoDescription: "Synthetic sample only · no live feeds or verified evidence connected.",
    entitiesCount: "Sample entities",
    relationshipsCount: "Sample relationships",
    stageTitle: "Relationship theater",
    viewMode: "Visualization mode",
    view2d: "2D map",
    view3d: "3D theater",
    mapLabel: "2D intelligence relationship map",
    mapDescription: "A visual overview of the synthetic entity and relationship sample.",
    mapLimitNotice: "Map shows {shown} of {total} relationships; use the explorer for the full list.",
    relationshipCountStatus: "Showing {shown} of {total} relationships.",
    showMoreRelationships: "Show more relationships",
    explorerTitle: "Intelligence graph explorer",
    entitiesTitle: "Entities",
    relationshipsTitle: "Relationships",
    selectedEntity: "Selected entity",
    entityType: "Entity type",
    confidence: "Confidence",
    illustrative: "illustrative only",
    evidence: "Evidence",
    noEvidence: "No verified evidence attached (demo).",
    provenance: "Provenance",
    keyboardHelp: "Use the arrow keys to move between related entities. Home and End move to the first and last entity.",
    graphicsChecking: "Checking graphics support…",
    graphicsReady: "WebGL is available. The 3D scene loads only when selected.",
    graphicsUnavailable: "3D is unavailable in this browser. The 2D map and graph explorer remain available.",
    loading3d: "Loading the 3D theater…",
    canvasFallback: "A WebGL context could not be created. Continue with the 2D relationship map.",
    switchTo2d: "Switch to 2D map",
    language: "Interface language",
    sampleSource: "Synthetic UI fixture",
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
    demoBadge: "بيانات تجريبية",
    demoDescription: "عينة اصطناعية فقط · لا توجد مصادر مباشرة أو أدلة موثقة متصلة.",
    entitiesCount: "كيانات العينة",
    relationshipsCount: "علاقات العينة",
    stageTitle: "مسرح العلاقات",
    viewMode: "نمط العرض",
    view2d: "خريطة ثنائية الأبعاد",
    view3d: "مسرح ثلاثي الأبعاد",
    mapLabel: "خريطة العلاقات الاستخباراتية ثنائية الأبعاد",
    mapDescription: "عرض مرئي لعينة الكيانات والعلاقات الاصطناعية.",
    mapLimitNotice: "تعرض الخريطة {shown} من أصل {total} علاقة؛ استخدم المستكشف للاطلاع على القائمة كاملة.",
    relationshipCountStatus: "يُعرض {shown} من أصل {total} علاقة.",
    showMoreRelationships: "عرض المزيد من العلاقات",
    explorerTitle: "مستكشف الرسم الاستخباراتي",
    entitiesTitle: "الكيانات",
    relationshipsTitle: "العلاقات",
    selectedEntity: "الكيان المحدد",
    entityType: "نوع الكيان",
    confidence: "درجة الثقة",
    illustrative: "توضيحية فقط",
    evidence: "الأدلة",
    noEvidence: "لا توجد أدلة موثقة مرفقة (بيانات تجريبية).",
    provenance: "المنشأ",
    keyboardHelp: "استخدم مفاتيح الأسهم للتنقل بين الكيانات المرتبطة. ينقلك مفتاحا Home وEnd إلى أول كيان وآخره.",
    graphicsChecking: "جارٍ التحقق من دعم الرسومات…",
    graphicsReady: "WebGL متاح. لن يُحمّل المشهد ثلاثي الأبعاد إلا عند اختياره.",
    graphicsUnavailable: "العرض ثلاثي الأبعاد غير متاح في هذا المتصفح. تظل الخريطة ومستكشف العلاقات متاحين.",
    loading3d: "جارٍ تحميل المسرح ثلاثي الأبعاد…",
    canvasFallback: "تعذّر إنشاء سياق WebGL. يمكنك المتابعة باستخدام خريطة العلاقات ثنائية الأبعاد.",
    switchTo2d: "الانتقال إلى الخريطة ثنائية الأبعاد",
    language: "لغة الواجهة",
    sampleSource: "بيانات اصطناعية لعرض الواجهة",
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
    demoBadge: "دادهٔ نمایشی",
    demoDescription: "فقط نمونهٔ ساختگی · هیچ خوراک زنده یا مدرک تأییدشده‌ای متصل نیست.",
    entitiesCount: "موجودیت‌های نمونه",
    relationshipsCount: "پیوندهای نمونه",
    stageTitle: "تالار پیوندها",
    viewMode: "حالت نمایش",
    view2d: "نقشهٔ دوبعدی",
    view3d: "تالار سه‌بعدی",
    mapLabel: "نقشهٔ دوبعدی پیوندهای اطلاعاتی",
    mapDescription: "نمایی بصری از نمونهٔ ساختگی موجودیت‌ها و پیوندها.",
    mapLimitNotice: "نقشه {shown} مورد از {total} پیوند را نشان می‌دهد؛ برای فهرست کامل از کاوشگر استفاده کنید.",
    relationshipCountStatus: "نمایش {shown} از {total} پیوند.",
    showMoreRelationships: "نمایش پیوندهای بیشتر",
    explorerTitle: "کاوشگر گراف اطلاعاتی",
    entitiesTitle: "موجودیت‌ها",
    relationshipsTitle: "پیوندها",
    selectedEntity: "موجودیت انتخاب‌شده",
    entityType: "نوع موجودیت",
    confidence: "میزان اطمینان",
    illustrative: "صرفاً نمایشی",
    evidence: "مدرک",
    noEvidence: "هیچ مدرک تأییدشده‌ای پیوست نشده است (نمونهٔ نمایشی).",
    provenance: "منشأ",
    keyboardHelp: "با کلیدهای جهت‌نما میان موجودیت‌های مرتبط جابه‌جا شوید. کلیدهای Home و End به ابتدا و انتها می‌روند.",
    graphicsChecking: "در حال بررسی پشتیبانی گرافیکی…",
    graphicsReady: "WebGL در دسترس است. صحنهٔ سه‌بعدی فقط هنگام انتخاب بارگیری می‌شود.",
    graphicsUnavailable: "نمای سه‌بعدی در این مرورگر در دسترس نیست. نقشه و کاوشگر پیوندها همچنان قابل استفاده‌اند.",
    loading3d: "در حال بارگیری تالار سه‌بعدی…",
    canvasFallback: "ایجاد زمینهٔ WebGL ممکن نشد. از نقشهٔ دوبعدی پیوندها استفاده کنید.",
    switchTo2d: "رفتن به نقشهٔ دوبعدی",
    language: "زبان رابط کاربری",
    sampleSource: "نمونهٔ ساختگی رابط کاربری",
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
