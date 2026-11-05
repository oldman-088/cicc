"use client";

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Locale } from "./localization";
import { ApplicationShell } from "./ApplicationShell";

type LocaleContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  reduceMotion: boolean;
  setReduceMotion: (reduceMotion: boolean) => void;
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
  const [reduceMotion, setReduceMotion] = useState(false);
  const localeValue = useMemo(
    () => ({ locale, setLocale, reduceMotion, setReduceMotion }),
    [locale, reduceMotion],
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
      if (window.localStorage.getItem("cicc:reduce-motion") === "true") {
        setReduceMotion(true);
      }
    } catch {
      // Keep the OS preference when browser storage is unavailable.
    }
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    if (reduceMotion) root.setAttribute("data-cicc-reduce-motion", "true");
    else root.removeAttribute("data-cicc-reduce-motion");

    try {
      window.localStorage.setItem("cicc:reduce-motion", String(reduceMotion));
    } catch {
      // The preference remains active for this app session without storage.
    }
  }, [reduceMotion]);

  return (
    <LocaleContext.Provider value={localeValue}>
      <ApplicationShell locale={locale} onLocaleChange={setLocale}>
        {children}
      </ApplicationShell>
    </LocaleContext.Provider>
  );
}
