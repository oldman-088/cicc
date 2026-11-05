"use client";

import { useState } from "react";
import { useCiccLocale } from "../application/CiccApplication";
import styles from "./TaskSubmissionPanel.module.css";

type SubmitState =
  | { phase: "idle" }
  | { phase: "pending" }
  | { phase: "accepted"; taskId: string; idempotencyKey: string | null }
  | { phase: "rejected"; message: string };

const copy = {
  en: { title: "Submit a coordination task", note: "Submissions go through the server-side BFF (fixed route, server-only write token). If writes are not enabled in this deployment, the server will refuse and say so — nothing is submitted silently.", kind: "Kind (lowercase, underscores)", taskTitle: "Title", submit: "Submit task", pending: "Submitting…", accepted: "Accepted by the provider. Task ID:", rejected: "Submission refused:", correlation: "Correlation (idempotency) key:" },
  ar: { title: "إرسال مهمة تنسيق", note: "تمر الإرسالات عبر BFF الخادمي (مسار ثابت، رمز كتابة خادمي فقط). إذا لم تكن الكتابة مفعّلة في هذا النشر فسيرفض الخادم بوضوح — لا يُرسل شيء بصمت.", kind: "النوع (أحرف صغيرة وشرطات سفلية)", taskTitle: "العنوان", submit: "إرسال المهمة", pending: "جارٍ الإرسال…", accepted: "قبله المزوّد. معرّف المهمة:", rejected: "رُفض الإرسال:", correlation: "مفتاح الارتباط (عدم التكرار):" },
  fa: { title: "ثبت وظیفهٔ هماهنگی", note: "ثبت‌ها از BFF سمت سرور می‌گذرند (مسیر ثابت، توکن نوشتن فقط سروری). اگر نوشتن در این استقرار فعال نباشد، سرور آشکارا رد می‌کند — چیزی بی‌صدا ثبت نمی‌شود.", kind: "نوع (حروف کوچک و زیرخط)", taskTitle: "عنوان", submit: "ثبت وظیفه", pending: "در حال ثبت…", accepted: "منبع پذیرفت. شناسهٔ وظیفه:", rejected: "ثبت رد شد:", correlation: "کلید هم‌بستگی (یکتایی):" },
} as const;

export function TaskSubmissionPanel() {
  const locale = useCiccLocale()?.locale ?? "en";
  const m = copy[locale];
  const [kind, setKind] = useState("frontend_task");
  const [title, setTitle] = useState("");
  const [state, setState] = useState<SubmitState>({ phase: "idle" });

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (state.phase === "pending") return; // no duplicate submissions
    setState({ phase: "pending" });
    try {
      const response = await fetch("/api/integrations/coordination/tasks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind, title }),
      });
      const body: unknown = await response.json().catch(() => null);
      if (response.ok && typeof body === "object" && body !== null && "task_id" in body) {
        setState({ phase: "accepted", taskId: String((body as { task_id: unknown }).task_id), idempotencyKey: response.headers.get("x-cicc-idempotency-key") });
      } else {
        const code = typeof body === "object" && body !== null && "error" in body ? String((body as { error: { code?: unknown } }).error.code ?? response.status) : String(response.status);
        setState({ phase: "rejected", message: code });
      }
    } catch {
      setState({ phase: "rejected", message: "unavailable" });
    }
  };

  return (
    <section className={styles.panel} aria-labelledby="task-submit-title" lang={locale} dir={locale === "en" ? "ltr" : "rtl"}>
      <h2 id="task-submit-title">{m.title}</h2>
      <p role="note">{m.note}</p>
      <form onSubmit={submit}>
        <label>{m.kind}<input value={kind} onChange={(e) => setKind(e.target.value)} pattern="[a-z0-9_]{1,64}" required /></label>
        <label>{m.taskTitle}<input value={title} onChange={(e) => setTitle(e.target.value)} required maxLength={500} /></label>
        <button type="submit" disabled={state.phase === "pending"}>{state.phase === "pending" ? m.pending : m.submit}</button>
      </form>
      <div aria-live="polite">
        {state.phase === "accepted" && <p>{m.accepted} <bdi dir="ltr">{state.taskId}</bdi>{state.idempotencyKey && <> · {m.correlation} <bdi dir="ltr">{state.idempotencyKey}</bdi></>}</p>}
        {state.phase === "rejected" && <p role="alert">{m.rejected} <bdi dir="ltr">{state.message}</bdi></p>}
      </div>
    </section>
  );
}
