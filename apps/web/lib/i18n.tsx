"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import en from "../messages/en.json";
import ar from "../messages/ar.json";
import { LOCALES, DEFAULT_LOCALE, RTL_MAP } from "./locales.mjs";

export type Locale = "en" | "ar";

const DICTS: Record<Locale, Record<string, string>> = { en, ar };
const LOCALE_LIST: readonly string[] = LOCALES as readonly string[];
const RTL_DIRS: Record<Locale, "ltr" | "rtl"> = RTL_MAP as Record<
  Locale,
  "ltr" | "rtl"
>;

interface LocaleContextValue {
  locale: Locale;
  setLocale: (l: Locale) => void;
  t: (key: string) => string;
  dir: "ltr" | "rtl";
}

const LocaleContext = createContext<LocaleContextValue | null>(null);

const STORAGE_KEY = "cicc-locale";

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE as Locale);

  // Restore persisted preference on mount (client only).
  useEffect(() => {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved && LOCALE_LIST.includes(saved)) {
      setLocaleState(saved as Locale);
    }
  }, []);

  // Apply lang/dir to <html> and persist the choice.
  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = RTL_DIRS[locale];
    window.localStorage.setItem(STORAGE_KEY, locale);
  }, [locale]);

  const setLocale = (l: Locale) => setLocaleState(l);
  const t = (key: string) => DICTS[locale][key] ?? key;

  return (
    <LocaleContext.Provider
      value={{ locale, setLocale, t, dir: RTL_DIRS[locale] }}
    >
      {children}
    </LocaleContext.Provider>
  );
}

export function useLocale(): LocaleContextValue {
  const ctx = useContext(LocaleContext);
  if (!ctx) throw new Error("useLocale must be used within LocaleProvider");
  return ctx;
}
