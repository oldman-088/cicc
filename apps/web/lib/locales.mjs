// Locale metadata shared by the React i18n provider and the node tests.
export const LOCALES = Object.freeze(["en", "ar"]);
export const DEFAULT_LOCALE = "en";
export const RTL_MAP = Object.freeze({ en: "ltr", ar: "rtl" });

export function isRTL(locale) {
  return RTL_MAP[locale] === "rtl";
}
