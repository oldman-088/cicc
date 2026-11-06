import { NextResponse } from "next/server";

// Server-side health aggregator: reports the web UI itself (this route
// responding = web is up) and performs a REAL check of the backend API by
// calling its /health endpoint. Browser clients only call the relative
// "/api/health" URL; this route takes precedence over the /api/* rewrite.
export const dynamic = "force-dynamic";

const apiInternalUrl = process.env.API_INTERNAL_URL || "http://127.0.0.1:8000";

export async function GET() {
  const started = Date.now();
  let backendStatus = "unreachable";
  let backendDetail: unknown = null;
  try {
    const res = await fetch(`${apiInternalUrl}/health`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });
    backendDetail = await res.json();
    backendStatus = res.ok ? "reachable" : "error";
  } catch {
    backendStatus = "unreachable";
  }
  const payload = {
    web: { status: "ok", response_ms: Date.now() - started },
    backend: { status: backendStatus, detail: backendDetail },
  };
  return NextResponse.json(payload, {
    status: backendStatus === "reachable" ? 200 : 503,
  });
}
