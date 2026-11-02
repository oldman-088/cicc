/** Partial demo translations; unknown and non-synthetic API data remain unchanged. */
export type DemoLocale = 'en' | 'ar' | 'fa';
export const demoLocales: readonly DemoLocale[] = ['en', 'ar', 'fa'];
export const isDemoLocale = (value: string | null): value is DemoLocale =>
  value !== null && demoLocales.includes(value as DemoLocale);

type Messages = { heading:string; subtitle:string; noticeTitle:string; notice:string; partial:string; navigationLabel:string; viewRecord:string; notificationsUnavailable:string; direction:'ltr'|'rtl' };
export const demoMessages: Record<DemoLocale, Messages> = {
  en: { heading:'Command Center', subtitle:'Your unified view of the cyber intelligence landscape.',
    noticeTitle:'Demonstration environment.', notice:'All intelligence shown is synthetic, historical example data. This demo is not connected to live sources.',
    partial:'Language support is partial; some interface text and records may remain in English.', navigationLabel:'Illustrative demo navigation', viewRecord:'View', notificationsUnavailable:'Notifications unavailable', direction:'ltr' },
  ar: { heading:'مركز القيادة', subtitle:'عرض موحّد لمشهد الاستخبارات السيبرانية.',
    noticeTitle:'بيئة تجريبية.', notice:'جميع المعلومات المعروضة بيانات تاريخية اصطناعية للتوضيح. هذه الواجهة غير متصلة بمصادر حية.',
    partial:'دعم اللغة جزئي؛ قد تبقى بعض نصوص الواجهة والسجلات باللغة الإنجليزية.', navigationLabel:'تنقل تجريبي للتوضيح', viewRecord:'عرض', notificationsUnavailable:'الإشعارات غير متاحة', direction:'rtl' },
  fa: { heading:'مرکز فرماندهی', subtitle:'نمایی یکپارچه از چشم‌انداز اطلاعات سایبری.',
    noticeTitle:'محیط آزمایشی.', notice:'همه اطلاعات نمایش‌داده‌شده داده‌های تاریخی و ساختگی برای نمایش هستند. این نمونه به منابع زنده متصل نیست.',
    partial:'پشتیبانی زبان ناقص است؛ برخی متن‌ها و رکوردها ممکن است انگلیسی بمانند.', navigationLabel:'ناوبری نمایشی نمونه', viewRecord:'مشاهده', notificationsUnavailable:'اعلان‌ها در دسترس نیستند', direction:'rtl' },
};

/** Partial navigation labels; entries are illustrative and do not navigate. */
export const navigationLabels = {
  'OVERVIEW':['Overview','نظرة عامة','نمای کلی'],
  'INTELLIGENCE':['Intelligence','الاستخبارات','اطلاعات'],
  'OPERATIONS':['Operations','العمليات','عملیات'],
  'SYSTEM':['System','النظام','سامانه'],
  'Command Center':['Command Center','مركز القيادة','مرکز فرماندهی'],
  'Global Landscape':['Global Landscape','المشهد العالمي','چشم‌انداز جهانی'],
  'Threat Intelligence':['Threat Intelligence','استخبارات التهديدات','اطلاعات تهدید'],
  'Vulnerabilities':['Vulnerabilities','الثغرات','آسیب‌پذیری‌ها'],
  'Threat Actors':['Threat Actors','جهات التهديد','عاملان تهدید'],
  'Campaigns':['Campaigns','الحملات','کارزارها'],
  'Indicators':['Indicators','المؤشرات','شاخص‌ها'],
  'Investigations':['Investigations','التحقيقات','تحقیقات'],
  'Assets & Exposure':['Assets & Exposure','الأصول والتعرض','دارایی‌ها و مواجهه'],
  'Reports':['Reports','التقارير','گزارش‌ها'],
  'Data Sources':['Data Sources','مصادر البيانات','منابع داده'],
  'Settings':['Settings','الإعدادات','تنظیمات'],
} as const;
export type NavigationLabel = keyof typeof navigationLabels;
export function navigationText(label: NavigationLabel, locale: DemoLocale): string {
  return navigationLabels[label][locale === 'en' ? 0 : locale === 'ar' ? 1 : 2];
}

export const panelLabels = {
  'SITUATIONAL AWARENESS':['Situational awareness','الوعي بالموقف','آگاهی از وضعیت'],
  'Global Intelligence Landscape':['Global Intelligence Landscape','المشهد الاستخباراتي العالمي','چشم‌انداز جهانی اطلاعات'],
  'Geographic visualization of intelligence activity':['Geographic visualization of intelligence activity','تصوّر جغرافي للنشاط الاستخباراتي','نمایش جغرافیایی فعالیت اطلاعاتی'],
  'GLOBAL VIEW':['Global view','عرض عالمي','نمای جهانی'],
  'No geographic data':['No geographic data','لا توجد بيانات جغرافية','داده جغرافیایی موجود نیست'],
  'Connect a source to view intelligence on the map':['Connect a source to view intelligence on the map','اربط مصدرًا لعرض المعلومات على الخريطة','برای نمایش اطلاعات روی نقشه یک منبع متصل کنید'],
  'ENVIRONMENT STATUS':['Environment status','حالة البيئة','وضعیت محیط'],
  'Intelligence Readiness':['Intelligence Readiness','جاهزية الاستخبارات','آمادگی اطلاعاتی'],
  'Current platform capabilities':['Current platform capabilities','قدرات المنصة الحالية','قابلیت‌های فعلی سامانه'],
  'Not production ready':['Not production ready','غير جاهز للإنتاج','برای محیط عملیاتی آماده نیست'],
  'This demo does not provide live collection or authentication.':['This demo does not provide live collection or authentication.','لا توفر هذه الواجهة التجريبية جمعًا مباشرًا أو مصادقة.','این نمونه گردآوری زنده یا احراز هویت ارائه نمی‌دهد.'],
  'INTELLIGENCE FEED':['Intelligence feed','موجز الاستخبارات','خوراک اطلاعاتی'],
  'Priority Intelligence':['Priority Intelligence','الاستخبارات ذات الأولوية','اطلاعات اولویت‌دار'],
  'Example records for analyst review':['Example records for analyst review','سجلات نموذجية لمراجعة المحلل','رکوردهای نمونه برای بررسی تحلیلگر'],
  'SYNTHETIC DATA':['Synthetic data','بيانات اصطناعية','داده ساختگی'],
  'COLLECTION STATUS':['Collection status','حالة الجمع','وضعیت گردآوری'],
  'Intelligence Sources':['Intelligence Sources','مصادر الاستخبارات','منابع اطلاعاتی'],
  'Connector availability':['Connector availability','توفر الموصلات','دسترس‌پذیری اتصال‌ها'],
  'This demo does not show the status of experimental connectors or synchronization attempts.':['This demo does not show the status of experimental connectors or synchronization attempts.','لا تعرض هذه الواجهة حالة الموصلات التجريبية أو محاولات المزامنة.','این نمونه وضعیت اتصال‌های آزمایشی یا تلاش‌های همگام‌سازی را نشان نمی‌دهد.'],
} as const;
export type PanelLabel = keyof typeof panelLabels;
export function panelText(label: PanelLabel, locale: DemoLocale): string {
  return panelLabels[label][locale === 'en' ? 0 : locale === 'ar' ? 1 : 2];
}

export const detailLabels = {
  'INTELLIGENCE ITEMS':['Intelligence items','عناصر الاستخبارات','موارد اطلاعاتی'],
  'Synthetic records':['Synthetic records','سجلات اصطناعية','رکوردهای ساختگی'],
  'CRITICAL ITEMS':['Critical items','العناصر الحرجة','موارد بحرانی'],
  'Requires analyst review':['Requires analyst review','يتطلب مراجعة المحلل','نیازمند بررسی تحلیلگر'],
  'DEMO SOURCES':['Demo sources','مصادر تجريبية','منابع نمونه'],
  'No live demo feeds':['No live demo feeds','لا توجد موجزات حية تجريبية','خوراک زنده‌ای در نمونه وجود ندارد'],
  'LIVE ACTIVITY':['Live activity','النشاط المباشر','فعالیت زنده'],
  'No live feed available':['No live feed available','لا يتوفر موجز حي','خوراک زنده موجود نیست'],
  'INTELLIGENCE':['Intelligence','الاستخبارات','اطلاعات'],
  'SEVERITY':['Severity','الخطورة','شدت'],
  'CONFIDENCE':['Confidence','الثقة','اطمینان'],
  'OBSERVED':['Observed','تاريخ الرصد','زمان مشاهده'],
  'Severity':['Severity','الخطورة','شدت'],
  'Example confidence':['Example confidence','الثقة النموذجية','اطمینان نمونه'],
  '(not factual certainty)':['(not factual certainty)','(ليست يقينًا واقعيًا)','(به معنای قطعیت واقعی نیست)'],
  'Source':['Source','المصدر','منبع'],
  'Example observed date':['Example observed date','تاريخ الرصد النموذجي','تاریخ مشاهده نمونه'],
  'Close details':['Close details','إغلاق التفاصيل','بستن جزئیات'],
  'Public intelligence source':['Public intelligence source','مصدر استخباراتي عام','منبع اطلاعاتی عمومی'],
  'Not connected':['Not connected','غير متصل','متصل نیست'],
  'Not available':['Not available','غير متاح','در دسترس نیست'],
  'Available':['Available','متاح','در دسترس'],
  'Demo intelligence sources':['Demo intelligence sources','مصادر استخبارات تجريبية','منابع اطلاعاتی نمونه'],
  'Demo authentication':['Demo authentication','مصادقة الواجهة التجريبية','احراز هویت نمونه'],
  'Synthetic dataset':['Synthetic dataset','مجموعة بيانات اصطناعية','مجموعه داده ساختگی'],
  'DEMO ENVIRONMENT':['Demo environment','بيئة تجريبية','محیط آزمایشی'],
  'NOT FOR OPERATIONAL USE':['Not for operational use','غير مخصص للاستخدام التشغيلي','برای استفاده عملیاتی نیست'],
} as const;
export type DetailLabel = keyof typeof detailLabels;
export function detailText(label: DetailLabel, locale: DemoLocale): string {
  return detailLabels[label][locale === 'en' ? 0 : locale === 'ar' ? 1 : 2];
}

/** Exact-match translations apply only to records explicitly marked synthetic. */
export const syntheticText: Record<string, readonly [string,string]> = {
  'Suspicious infrastructure cluster':['مجموعة بنية تحتية مشبوهة','خوشه زیرساخت مشکوک'],
  'Credential phishing campaign':['حملة تصيد بيانات اعتماد','کارزار فیشینگ اطلاعات ورود'],
  'Potentially exposed service':['خدمة قد تكون مكشوفة','خدمت احتمالاً در معرض دسترس'],
  'Malware family association':['ارتباط بعائلة برمجيات خبيثة','ارتباط با خانواده بدافزار'],
  'Example infrastructure relationship for training; not an observed threat.':['علاقة بنية تحتية نموذجية للتدريب؛ ليست تهديدًا مرصودًا.','رابطه نمونه زیرساخت برای آموزش؛ تهدید مشاهده‌شده نیست.'],
  'Illustrative campaign record with no real-world attribution.':['سجل حملة توضيحي دون إسناد في العالم الحقيقي.','رکورد کارزار نمایشی بدون انتساب در دنیای واقعی.'],
  'Example exposure requiring analyst verification.':['حالة تعرض نموذجية تتطلب تحقق المحلل.','نمونه مواجهه که نیازمند بررسی تحلیلگر است.'],
  'Fictional association included for interface demonstration.':['ارتباط خيالي أُدرج لعرض الواجهة.','ارتباط خیالی برای نمایش رابط درج شده است.'],
  'Infrastructure':['البنية التحتية','زیرساخت'], 'Campaign':['حملة','کارزار'],
  'Exposure':['التعرض','مواجهه'], 'Malware':['برمجيات خبيثة','بدافزار'],
  'Critical':['حرج','بحرانی'], 'High':['مرتفع','بالا'], 'Medium':['متوسط','متوسط'],
  'Synthetic exercise':['تمرين اصطناعي','تمرین ساختگی'],
};
export function syntheticValue(value: string, locale: DemoLocale, synthetic: boolean): {text:string; lang?:DemoLocale; dir:'ltr'|'rtl'|'auto'} {
  const translated = synthetic && locale !== 'en' && Object.prototype.hasOwnProperty.call(syntheticText,value) ? syntheticText[value] : undefined;
  return translated ? {text:translated[locale === 'ar' ? 0 : 1],lang:locale,dir:'rtl'} : {text:value,dir:'auto'};
}

export const miscLabels = {
  'INTELLIGENCE PLATFORM':['Intelligence platform','منصة الاستخبارات','سامانه اطلاعاتی'],
  'DEMO WORKSPACE':['Demo workspace','مساحة عمل تجريبية','فضای کاری نمونه'],
  'Need assistance?':['Need assistance?','هل تحتاج إلى مساعدة؟','به کمک نیاز دارید؟'],
  'Platform documentation':['Platform documentation','وثائق المنصة','مستندات سامانه'],
  'Demo Analyst':['Demo Analyst','محلل تجريبي','تحلیلگر نمونه'],
  'Local demonstration':['Local demonstration','عرض تجريبي محلي','نمایش محلی'],
  'Overview':['Overview','نظرة عامة','نمای کلی'],
  'Command Center':['Command Center','مركز القيادة','مرکز فرماندهی'],
  'DEMO MODE':['Demo mode','الوضع التجريبي','حالت آزمایشی'],
  'INTELLIGENCE OVERVIEW':['Intelligence overview','نظرة عامة على الاستخبارات','نمای کلی اطلاعات'],
  'DATA ENVIRONMENT':['Data environment','بيئة البيانات','محیط داده'],
  'Synthetic demonstration':['Synthetic demonstration','عرض ببيانات اصطناعية','نمایش با داده ساختگی'],
  'Intelligence API unavailable. Start the API service and refresh this page.':['Intelligence API unavailable. Start the API service and refresh this page.','واجهة الاستخبارات غير متاحة. شغّل خدمة الواجهة وأعد تحميل الصفحة.','رابط اطلاعاتی در دسترس نیست. سرویس را اجرا و صفحه را بازخوانی کنید.'],
  'Loading demonstration intelligence…':['Loading demonstration intelligence…','جارٍ تحميل المعلومات التجريبية…','در حال بارگذاری اطلاعات نمونه…'],
  'VISUALIZATION PLACEHOLDER':['Visualization placeholder','عنصر مرئي توضيحي','نمایش موقت'],
  'NO LIVE EVENTS':['No live events','لا توجد أحداث حية','رویداد زنده‌ای وجود ندارد'],
  'Geographic activity':['Geographic activity','النشاط الجغرافي','فعالیت جغرافیایی'],
  'Awaiting configured sources':['Awaiting configured sources','بانتظار مصادر مُهيأة','در انتظار منابع پیکربندی‌شده'],
  'DEMO':['Demo','تجريبي','نمونه'],
  'ENVIRONMENT':['Environment','بيئة','محیط'],
  'Click a record to inspect details':['Click a record to inspect details','انقر على سجل لعرض التفاصيل','برای مشاهده جزئیات یک رکورد را انتخاب کنید'],
  'CYBER INTELLIGENCE COMMAND CENTER':['Cyber Intelligence Command Center','مركز قيادة الاستخبارات السيبرانية','مرکز فرماندهی اطلاعات سایبری'],
  'SYNTHETIC INTELLIGENCE':['Synthetic intelligence','استخبارات اصطناعية','اطلاعات ساختگی'],
  'not configured':['Not configured','غير مُهيأ','پیکربندی نشده'],
} as const;
export type MiscLabel = keyof typeof miscLabels;
export function miscText(label: MiscLabel, locale: DemoLocale): string {
  return miscLabels[label][locale === 'en' ? 0 : locale === 'ar' ? 1 : 2];
}
export function recordCount(count: number, locale: DemoLocale): string {
  if (locale === 'ar') return `عرض ${count} من السجلات التجريبية`;
  if (locale === 'fa') return `نمایش ${count} رکورد نمونه`;
  return `Showing ${count} demonstration records`;
}
