export function buildUpstreamHeaders(clientHeaders: Headers, env: Record<string, string | undefined>): Headers;
export function isWriteAllowed(method: string, env: Record<string, string | undefined>): boolean;
export function sameOriginOk(headers: Headers, env: Record<string, string | undefined>): boolean;
export function buildUpstreamUrl(apiInternalUrl: string | undefined, pathSegments: string[], search: string): string;
export function safeLogFields(method: string, path: string, status: number): { method: string; path: string; status: number };
