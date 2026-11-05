"use client";

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { isLocale, type Locale } from "./localization";
import { ApplicationShell } from "./ApplicationShell";

export type CiccTheme = "dark" | "light";

type LocaleContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  reduceMotion: boolean;
  setReduceMotion: (reduceMotion: boolean) => void;
  /** Master Prompt §3.1: dark command-center interface with an optional light theme. */
  theme: CiccTheme;
  setTheme: (theme: CiccTheme) => void;
};

const LocaleContext = createContext<LocaleContextValue | null>(null);

export function useCiccLocale() {
  const context = useContext(LocaleContext);
  return context ? { locale: context.locale, setLocale: context.setLocale } : null;
}

export function useCiccPreferences() {
  return useContext(LocaleContext);
}

export function CiccApplication({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>("en");
  const [theme, setTheme] = useState<CiccTheme>("dark");
  const [reduceMotion, setReduceMotion] = useState(false);
  const [preferencesReady, setPreferencesReady] = useState(false);
  const localeValue = useMemo(
    () => ({ locale, setLocale, reduceMotion, setReduceMotion, theme, setTheme }),
    [locale, reduceMotion, theme],
  );

  useEffect(() => {
    const root = document.documentElement;
    const originalLanguage = root.lang;
    const originalDirection = root.dir;
    const originalMotionPreference = root.getAttribute("data-cicc-reduce-motion");
    return () => {
      root.lang = originalLanguage;
      root.dir = originalDirection;
      if (originalMotionPreference === null) root.removeAttribute("data-cicc-reduce-motion");
      else root.setAttribute("data-cicc-reduce-motion", originalMotionPreference);
    };
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = locale === "en" ? "ltr" : "rtl";
  }, [locale]);

  useEffect(() => {
    try {
      const storedLocale = window.localStorage.getItem("cicc:locale");
      if (storedLocale && isLocale(storedLocale)) setLocale(storedLocale);
      setReduceMotion(window.localStorage.getItem("cicc:reduce-motion") === "true");
      if (window.localStorage.getItem("cicc:theme") === "light") setTheme("light");
    } catch {
      // Preferences still work for this session when browser storage is unavailable.
    }
    setPreferencesReady(true);
  }, []);

  useEffect(() => {
    if (!preferencesReady) return;
    const root = document.documentElement;
    if (reduceMotion) root.setAttribute("data-cicc-reduce-motion", "true");
    else root.removeAttribute("data-cicc-reduce-motion");

    try {
      window.localStorage.setItem("cicc:reduce-motion", String(reduceMotion));
    } catch {
      // The preference remains active for this app session without storage.
    }
  }, [reduceMotion, preferencesReady]);

  useEffect(() => {
    if (!preferencesReady) return;
    const root = document.documentElement;
    if (theme === "light") root.setAttribute("data-cicc-theme", "light");
    else root.removeAttribute("data-cicc-theme");
    try {
      window.localStorage.setItem("cicc:theme", theme);
    } catch {
      // Theme remains active for this session without storage.
    }
  }, [theme, preferencesReady]);

  useEffect(() => {
    if (!preferencesReady) return;
    try {
      window.localStorage.setItem("cicc:locale", locale);
    } catch {
      // Locale selection remains active for this app session without storage.
    }
  }, [locale, preferencesReady]);

  return (
    <LocaleContext.Provider value={localeValue}>
      <ApplicationShell locale={locale} onLocaleChange={setLocale}>
        {children}
      </ApplicationShell>
    </LocaleContext.Provider>
  );
}
