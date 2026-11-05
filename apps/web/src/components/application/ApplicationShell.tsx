"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { isLocale, type Locale } from "./localization";
import styles from "./ApplicationShell.module.css";

type ApplicationShellProps = {
  locale: Locale;
  onLocaleChange: (locale: Locale) => void;
  children: ReactNode;
};

type ShellMessages = {
  skipToContent: string;
  brandDescription: string;
  breadcrumb: string;
  workspace: string;
  overview: string;
  threatIntelligence: string;
  vulnerabilityIntelligence: string;
  commandTheater: string;
  systemHealth: string;
  coordination: string;
  settings: string;
  unknownPage: string;
  navigation: string;
  workspaceSection: string;
  settingsSection: string;
  availabilityTitle: string;
  availabilityDescription: string;
  searchPages: string;
  searchHelp: string;
  searchShortcutLabel: string;
  noPagesMatch: string;
  language: string;
  openNavigation: string;
  closeNavigation: string;
};

const shellMessages: Record<Locale, ShellMessages> = {
  en: {
    skipToContent: "Skip to main content",
    brandDescription: "Cyber Intelligence Command Center",
    breadcrumb: "Breadcrumb",
    workspace: "Workspace",
    overview: "Overview",
    threatIntelligence: "Threat Intelligence",
    vulnerabilityIntelligence: "Vulnerability Intelligence",
    commandTheater: "Command Theater",
    systemHealth: "System Health",
    coordination: "Agent Coordination",
    settings: "Settings",
    unknownPage: "Page not found",
    navigation: "Primary navigation",
    workspaceSection: "Workspace",
    settingsSection: "Preferences",
    availabilityTitle: "Integration status",
    availabilityDescription: "Pages without a verified data provider show an explicit not-connected state. No production data is synthesized.",
    searchPages: "Find a workspace page",
    searchHelp: "Searches pages only. Entity search requires a connected, verified data provider.",
    searchShortcutLabel: "Shortcut",
    noPagesMatch: "No workspace page matches this search.",
    language: "Interface language",
    openNavigation: "Open workspace navigation",
    closeNavigation: "Close workspace navigation",
  },
  ar: {
    skipToContent: "تخطَّ إلى المحتوى الرئيسي",
    brandDescription: "مركز قيادة الاستخبارات السيبرانية",
    breadcrumb: "مسار التنقل",
    workspace: "مساحة العمل",
    overview: "نظرة عامة",
    threatIntelligence: "استخبارات التهديدات",
    vulnerabilityIntelligence: "استخبارات الثغرات",
    commandTheater: "مسرح القيادة",
    systemHealth: "سلامة النظام",
    coordination: "تنسيق الوكلاء",
    settings: "الإعدادات",
    unknownPage: "الصفحة غير موجودة",
    navigation: "التنقل الرئيسي",
    workspaceSection: "مساحة العمل",
    settingsSection: "التفضيلات",
    availabilityTitle: "حالة التكامل",
    availabilityDescription: "تعرض الصفحات التي لا تملك مزوّد بيانات موثّق حالة عدم الاتصال بوضوح. لا تُنشأ بيانات إنتاجية مصطنعة.",
    searchPages: "البحث عن صفحة في مساحة العمل",
    searchHelp: "يبحث في الصفحات فقط. يتطلب البحث عن الكيانات مزوّد بيانات متصلاً وموثّقاً.",
    searchShortcutLabel: "اختصار",
    noPagesMatch: "لا توجد صفحة في مساحة العمل تطابق هذا البحث.",
    language: "لغة الواجهة",
    openNavigation: "فتح تنقل مساحة العمل",
    closeNavigation: "إغلاق تنقل مساحة العمل",
  },
  fa: {
    skipToContent: "رفتن به محتوای اصلی",
    brandDescription: "مرکز فرماندهی اطلاعات سایبری",
    breadcrumb: "مسیر راهنما",
    workspace: "فضای کاری",
    overview: "نمای کلی",
    threatIntelligence: "اطلاعات تهدید",
    vulnerabilityIntelligence: "اطلاعات آسیب‌پذیری",
    commandTheater: "تالار فرماندهی",
    systemHealth: "سلامت سامانه",
    coordination: "هماهنگی عامل‌ها",
    settings: "تنظیمات",
    unknownPage: "صفحه پیدا نشد",
    navigation: "پیمایش اصلی",
    workspaceSection: "فضای کاری",
    settingsSection: "ترجیحات",
    availabilityTitle: "وضعیت یکپارچه‌سازی",
    availabilityDescription: "صفحه‌هایی که منبع دادهٔ تأییدشده ندارند، وضعیت اتصال‌نداشتن را روشن نشان می‌دهند. دادهٔ عملیاتی ساختگی تولید نمی‌شود.",
    searchPages: "یافتن صفحهٔ فضای کاری",
    searchHelp: "فقط صفحه‌ها جست‌وجو می‌شوند. جست‌وجوی موجودیت به منبع دادهٔ متصل و تأییدشده نیاز دارد.",
    searchShortcutLabel: "میان‌بر",
    noPagesMatch: "صفحه‌ای در فضای کاری با این جست‌وجو پیدا نشد.",
    language: "زبان رابط کاربری",
    openNavigation: "بازکردن پیمایش فضای کاری",
    closeNavigation: "بستن پیمایش فضای کاری",
  },
};

type NavigationItem = {
  id: "overview" | "threat-intelligence" | "vulnerability-intelligence" | "command-theater" | "system-health" | "coordination" | "settings";
  href: string;
  label: string;
};

function NavigationGlyph({ id }: { id: NavigationItem["id"] }) {
  return (
    <span className={styles.navigationGlyph} aria-hidden="true">
      <svg viewBox="0 0 24 24" focusable="false">
        {id === "overview" && <>
          <rect x="4" y="4" width="7" height="7" rx="1.5" />
          <rect x="13" y="4" width="7" height="4" rx="1.2" />
          <rect x="13" y="10" width="7" height="10" rx="1.5" />
          <rect x="4" y="13" width="7" height="7" rx="1.5" />
        </>}
        {id === "threat-intelligence" && <>
          <circle cx="12" cy="12" r="3" />
          <path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1" />
        </>}
        {id === "vulnerability-intelligence" && <>
          <path d="M12 3 20 6v5c0 5-3.4 8.2-8 10-4.6-1.8-8-5-8-10V6z" />
          <path d="M12 8v5m0 3h.01" />
        </>}
        {id === "command-theater" && <>
          <circle cx="6" cy="7" r="2" />
          <circle cx="18" cy="6" r="2" />
          <circle cx="12" cy="18" r="2" />
          <path d="m8 7 8-1M7 9l4 7m6-8-4 8" />
        </>}
        {id === "system-health" && <>
          <path d="M3 12h4l2-6 4 12 2-6h6" />
          <circle cx="3" cy="12" r="1" />
          <circle cx="21" cy="12" r="1" />
        </>}
        {id === "coordination" && <>
          <circle cx="12" cy="5" r="2" />
          <circle cx="6" cy="18" r="2" />
          <circle cx="18" cy="18" r="2" />
          <path d="m11 7-4 9m6-9 4 9M8 18h8" />
        </>}
        {id === "settings" && <>
          <circle cx="12" cy="12" r="3" />
          <path d="m19.4 15 .1.1 1.2 1-.9 1.6-1.5-.4a8 8 0 0 1-1.5.9l-.3 1.6h-1.9l-.3-1.6a8 8 0 0 1-1.7 0l-.9 1.3-1.7-.6.1-1.6a8 8 0 0 1-1.2-1.2l-1.6.1-.6-1.8 1.4-.8a8 8 0 0 1 0-1.7l-1.3-.9.6-1.7 1.6.1A8 8 0 0 1 8.3 8l-.1-1.6 1.8-.6.8 1.4a8 8 0 0 1 1.7 0l.9-1.3 1.7.6-.1 1.6a8 8 0 0 1 1.2 1.2l1.6-.1.6 1.8-1.4.8a8 8 0 0 1 0 1.7l1.3.9-.6 1.7z" />
        </>}
      </svg>
    </span>
  );
}

export function ApplicationShell({ locale, onLocaleChange, children }: ApplicationShellProps) {
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);
  const [navigationQuery, setNavigationQuery] = useState("");
  const navigationId = useId();
  const searchHelpId = useId();
  const searchInputRef = useRef<HTMLInputElement>(null);
  const messages = shellMessages[locale];
  const pathname = usePathname() ?? "/";

  useEffect(() => {
    function focusNavigationSearch(event: KeyboardEvent) {
      if (
        !(event.ctrlKey || event.metaKey)
        || event.altKey
        || event.shiftKey
        || event.key.toLowerCase() !== "k"
        || event.defaultPrevented
      ) return;

      const target = event.target;
      if (target instanceof HTMLElement && (
        target.isContentEditable
        || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)
      )) return;

      event.preventDefault();
      setMobileNavigationOpen(true);
      window.setTimeout(() => {
        searchInputRef.current?.focus();
        searchInputRef.current?.select();
      }, 0);
    }

    window.addEventListener("keydown", focusNavigationSearch);
    return () => window.removeEventListener("keydown", focusNavigationSearch);
  }, []);

  const workspaceItems: NavigationItem[] = [
    { id: "overview", href: "/", label: messages.overview },
    { id: "threat-intelligence", href: "/threat-intelligence", label: messages.threatIntelligence },
    { id: "vulnerability-intelligence", href: "/vulnerability-intelligence", label: messages.vulnerabilityIntelligence },
    { id: "command-theater", href: "/command-theater", label: messages.commandTheater },
    { id: "system-health", href: "/system-health", label: messages.systemHealth },
    { id: "coordination", href: "/coordination", label: messages.coordination },
  ];
  const settingsItem: NavigationItem = { id: "settings", href: "/settings", label: messages.settings };
  const allItems = [...workspaceItems, settingsItem];
  const currentItem = allItems.find((item) => isCurrentRoute(pathname, item.href));
  const currentPage = currentItem?.label ?? messages.unknownPage;
  const normalizedQuery = navigationQuery.trim().toLocaleLowerCase(locale);
  const matchesQuery = (item: NavigationItem) => item.label.toLocaleLowerCase(locale).includes(normalizedQuery);
  const visibleWorkspaceItems = workspaceItems.filter(matchesQuery);
  const showSettings = matchesQuery(settingsItem);
  const hasMatches = visibleWorkspaceItems.length > 0 || showSettings;

  function changeLocale(value: string) {
    if (isLocale(value)) onLocaleChange(value);
  }

  function renderNavigationItem(item: NavigationItem) {
    const isCurrent = isCurrentRoute(pathname, item.href);
    return (
      <li key={item.id}>
        <Link
          className={styles.navigationLink}
          href={item.href}
          aria-current={isCurrent ? "page" : undefined}
          onClick={() => setMobileNavigationOpen(false)}
        >
          <NavigationGlyph id={item.id} />
          <span>{item.label}</span>
          {isCurrent && <span className={styles.currentMarker} aria-hidden="true" />}
        </Link>
      </li>
    );
  }

  return (
    <div className={styles.root} lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <a className={styles.skipLink} href="#cicc-main-content">
        {messages.skipToContent}
      </a>

      <header className={styles.topbar}>
        <Link className={styles.brand} href="/" aria-label={messages.brandDescription}>
          <span className={styles.brandMark} aria-hidden="true">
            <svg viewBox="0 0 32 32" focusable="false">
              <path d="M7 9.5 16 5l9 4.5v13L16 27l-9-4.5z" />
              <path d="m7.5 10 8.5 4.5 8.5-4.5M16 14.5V26" />
              <circle cx="7" cy="9.5" r="1.5" />
              <circle cx="16" cy="5" r="1.5" />
              <circle cx="25" cy="9.5" r="1.5" />
              <circle cx="16" cy="14.5" r="1.5" />
            </svg>
          </span>
          <span className={styles.brandCopy}>
            <span className={styles.brandName}><bdi dir="ltr">CICC</bdi></span>
            <span className={styles.brandDescription}>{messages.brandDescription}</span>
          </span>
        </Link>

        <nav className={styles.breadcrumb} aria-label={messages.breadcrumb}>
          <ol>
            <li>{messages.workspace}</li>
            <li className={styles.breadcrumbDivider} aria-hidden="true">/</li>
            <li aria-current="page">{currentPage}</li>
          </ol>
        </nav>

        <div className={styles.headerActions}>
          <label className={styles.localeControl}>
            <span className={styles.visuallyHidden}>{messages.language}</span>
            <select
              aria-label={messages.language}
              value={locale}
              onChange={(event) => changeLocale(event.target.value)}
            >
              <option value="en">English</option>
              <option value="ar">العربية</option>
              <option value="fa">فارسی</option>
            </select>
          </label>
          <button
            className={styles.navigationToggle}
            type="button"
            aria-controls={navigationId}
            aria-expanded={mobileNavigationOpen}
            aria-label={mobileNavigationOpen ? messages.closeNavigation : messages.openNavigation}
            onClick={() => setMobileNavigationOpen((open) => !open)}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              {mobileNavigationOpen
                ? <path d="m6 6 12 12M18 6 6 18" />
                : <path d="M4 7h16M4 12h16M4 17h16" />}
            </svg>
          </button>
        </div>
      </header>

      <div className={styles.workspaceLayout}>
        <aside
          className={styles.sidebar}
          data-mobile-open={mobileNavigationOpen}
        >
          <nav id={navigationId} aria-label={messages.navigation}>
            <div className={styles.navSearch} role="search" aria-label={messages.searchPages}>
              <span className={styles.navSearchIcon} aria-hidden="true">
                <svg viewBox="0 0 24 24" focusable="false">
                  <circle cx="10.8" cy="10.8" r="6.3" />
                  <path d="m15.5 15.5 4.2 4.2" />
                </svg>
              </span>
              <input
                ref={searchInputRef}
                type="search"
                aria-label={messages.searchPages}
                aria-describedby={searchHelpId}
                aria-keyshortcuts="Control+K Meta+K"
                value={navigationQuery}
                onChange={(event) => setNavigationQuery(event.target.value)}
                placeholder={messages.searchPages}
              />
            </div>
            <p className={styles.searchHelp} id={searchHelpId}>
              {messages.searchHelp}
              <span className={styles.searchShortcut}>
                {messages.searchShortcutLabel}
                <kbd dir="ltr"><bdi dir="ltr">Ctrl/⌘+K</bdi></kbd>
              </span>
            </p>

            <p className={styles.sectionLabel}>{messages.workspaceSection}</p>
            <ul className={styles.navigationList}>
              {visibleWorkspaceItems.map(renderNavigationItem)}
            </ul>

            {showSettings && <>
              <p className={`${styles.sectionLabel} ${styles.settingsSection}`}>{messages.settingsSection}</p>
              <ul className={styles.navigationList}>{renderNavigationItem(settingsItem)}</ul>
            </>}

            {!hasMatches && <p className={styles.noSearchResults} role="status">{messages.noPagesMatch}</p>}
          </nav>

          <div className={styles.sidebarNote}>
            <span className={styles.noteLabel}>{messages.availabilityTitle}</span>
            <p>{messages.availabilityDescription}</p>
          </div>
        </aside>

        <main id="cicc-main-content" className={styles.main} tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}

function isCurrentRoute(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}
