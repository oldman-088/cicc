"use client";

import Link from "next/link";
import { useCiccLocale } from "../components/application/CiccApplication";

const copy = {
  en: { title: "Something went wrong", body: "This page failed to render. No data was fabricated in its place. You can retry, or return to the overview.", retry: "Retry", home: "Return to overview" },
  ar: { title: "حدث خطأ ما", body: "تعذّر عرض هذه الصفحة. لم تُختلق بيانات مكانها. يمكنك المحاولة مجدداً أو العودة إلى النظرة العامة.", retry: "إعادة المحاولة", home: "العودة إلى النظرة العامة" },
  fa: { title: "خطایی رخ داد", body: "نمایش این صفحه ممکن نشد. داده‌ای به‌جای آن ساخته نشد. می‌توانید دوباره تلاش کنید یا به نمای کلی بازگردید.", retry: "تلاش دوباره", home: "بازگشت به نمای کلی" },
} as const;

export default function RouteError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  const locale = useCiccLocale()?.locale ?? "en";
  const m = copy[locale];
  return (
    <main lang={locale} dir={locale === "en" ? "ltr" : "rtl"} style={{ padding: "2rem", maxWidth: "42rem", margin: "0 auto" }}>
      <h1>{m.title}</h1>
      <p role="alert">{m.body}</p>
      <p>
        <button type="button" onClick={() => reset()}>{m.retry}</button>{" "}
        <Link href="/">{m.home}</Link>
      </p>
    </main>
  );
}
