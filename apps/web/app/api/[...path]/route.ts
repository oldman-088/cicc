import { NextRequest, NextResponse } from "next/server";
import {
  buildUpstreamHeaders,
  buildUpstreamUrl,
  isWriteAllowed,
  isCoordWriteAllowed,
  validateCoordTaskBody,
  coordWriteToken,
  MAX_WRITE_BODY_BYTES,
  sameOriginOk,
  safeLogFields,
} from "../../../lib/bff.mjs";
import { randomUUID } from "crypto";

// Server-side BFF proxy for /api/* (M14-03). The browser only ever calls
// relative "/api/..." URLs with NO token; this handler injects the server-side
// token from WEB_BFF_API_TOKEN (server env only — never shipped to the client).
export const dynamic = "force-dynamic";

const apiInternalUrl = process.env.API_INTERNAL_URL || "http://127.0.0.1:8000";

async function proxy(req: NextRequest, pathSegments: string[]) {
  const path = pathSegments.join("/");
  const coordWrite = isCoordWriteAllowed(req.method, pathSegments, process.env);
  if (!coordWrite && !isWriteAllowed(req.method, process.env)) {
    return NextResponse.json({ detail: "method_not_allowed_via_bff" }, { status: 403 });
  }
  if (!sameOriginOk(req.headers, process.env)) {
    return NextResponse.json({ detail: "cross_site_forbidden" }, { status: 403 });
  }
  const url = buildUpstreamUrl(apiInternalUrl, pathSegments, req.nextUrl.search);
  const headers = buildUpstreamHeaders(req.headers, process.env);
  let body: ArrayBuffer | undefined =
    req.method === "GET" || req.method === "HEAD" ? undefined : await req.arrayBuffer();
  let serverIdempotencyKey: string | undefined;
  if (coordWrite) {
    // M26 approved write path: POST /api/v1/coordination/tasks only.
    // Separate server-only write token, strict DTO allowlist, server-generated
    // idempotency_key (the execution correlation key). Client auth was already
    // stripped by buildUpstreamHeaders; we inject the write token here.
    if ((body?.byteLength ?? 0) > MAX_WRITE_BODY_BYTES) {
      return NextResponse.json({ detail: "payload_too_large" }, { status: 413 });
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(body ?? new ArrayBuffer(0)));
    } catch {
      return NextResponse.json({ detail: "invalid_json" }, { status: 422 });
    }
    const v = validateCoordTaskBody(parsed, () => `bff-${randomUUID()}`);
    if (!v.ok) {
      return NextResponse.json({ detail: "invalid_request", reason: v.error }, { status: 422 });
    }
    // M33: expose the server-generated correlation key on the write response
    // (additive response header; the key is also persisted and readable via GET)
    serverIdempotencyKey = (v.value as { idempotency_key?: string }).idempotency_key;
    body = new TextEncoder().encode(JSON.stringify(v.value)).buffer as ArrayBuffer;
    headers.set("Authorization", `Bearer ${coordWriteToken(process.env)}`);
    headers.set("Content-Type", "application/json");
  }
  try {
    const res = await fetch(url, {
      method: req.method,
      headers,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
    const buf = await res.arrayBuffer();
    const out = new Headers();
    if (coordWrite && serverIdempotencyKey) out.set("x-cicc-idempotency-key", serverIdempotencyKey);
    res.headers.forEach((v, k) => {
      if (!["content-encoding", "transfer-encoding", "connection"].includes(k.toLowerCase()))
        out.set(k, v);
    });
    // never log tokens/headers — only method, path, status
    console.info("bff", JSON.stringify(safeLogFields(req.method, path, res.status)));
    return new NextResponse(buf, { status: res.status, headers: out });
  } catch {
    console.info("bff", JSON.stringify(safeLogFields(req.method, path, 502)));
    return NextResponse.json({ detail: "upstream_unreachable" }, { status: 502 });
  }
}

export async function GET(req: NextRequest, ctx: { params: { path: string[] } }) {
  return proxy(req, ctx.params.path);
}
export async function POST(req: NextRequest, ctx: { params: { path: string[] } }) {
  return proxy(req, ctx.params.path);
}
export async function PUT(req: NextRequest, ctx: { params: { path: string[] } }) {
  return proxy(req, ctx.params.path);
}
export async function PATCH(req: NextRequest, ctx: { params: { path: string[] } }) {
  return proxy(req, ctx.params.path);
}
export async function DELETE(req: NextRequest, ctx: { params: { path: string[] } }) {
  return proxy(req, ctx.params.path);
}
