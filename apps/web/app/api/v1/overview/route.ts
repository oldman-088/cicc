import { NextResponse } from 'next/server';
import { isDemoOverview } from '../../../demo-overview';

// Runtime-only server-side URL; the browser never contacts the API host directly.
// Only the fixed public demo endpoint is proxied, with a bounded synthetic-only contract.
export const dynamic = 'force-dynamic';
const MAX_BYTES = 256 * 1024;
const unavailable = (status:number) => NextResponse.json({ error: 'Intelligence API unavailable' }, {status, headers:{'Cache-Control':'no-store'}});
export async function GET() {
  try {
    const base = process.env.API_INTERNAL_URL || 'http://127.0.0.1:8000';
    const response = await fetch(`${base.replace(/\/$/, '')}/api/v1/overview`, {
      cache: 'no-store', signal: AbortSignal.timeout(5000), redirect: 'error',
    });
    if (!response.ok || !response.body) return unavailable(502);
    const reader = response.body.getReader();
    const chunks:Uint8Array[] = [];
    let length = 0;
    while (true) {
      const {done,value} = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BYTES) { await reader.cancel(); return unavailable(502); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk,offset); offset += chunk.length; }
    let value:unknown;
    try { value = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes)); }
    catch { return unavailable(502); }
    if (!isDemoOverview(value)) return unavailable(502);
    return NextResponse.json(value, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return unavailable(503);
  }
}
