import { NextRequest, NextResponse } from "next/server";
import {
  buildUpstreamHeaders,
  buildUpstreamUrl,
  isWriteAllowed,
  sameOriginOk,
  safeLogFields,
} from "../../../lib/bff.mjs";

// Server-side BFF proxy for /api/* (M14-03). The browser only ever calls
// relative "/api/..." URLs with NO token; this handler injects the server-side
// token from WEB_BFF_API_TOKEN (server env only — never shipped to the client).
export const dynamic = "force-dynamic";

const apiInternalUrl = process.env.API_INTERNAL_URL || "http://127.0.0.1:8000";

async function proxy(req: NextRequest, pathSegments: string[]) {
  const path = pathSegments.join("/");
  if (!isWriteAllowed(req.method, process.env)) {
    return NextResponse.json({ detail: "method_not_allowed_via_bff" }, { status: 403 });
  }
  if (!sameOriginOk(req.headers, process.env)) {
    return NextResponse.json({ detail: "cross_site_forbidden" }, { status: 403 });
  }
  const url = buildUpstreamUrl(apiInternalUrl, pathSegments, req.nextUrl.search);
  const headers = buildUpstreamHeaders(req.headers, process.env);
  const body =
    req.method === "GET" || req.method === "HEAD" ? undefined : await req.arrayBuffer();
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
