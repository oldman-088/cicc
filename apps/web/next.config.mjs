/** @type {import('next').NextConfig} */

// M14-03: /api/* is handled by the server-side BFF route handler
// (app/api/[...path]/route.ts), which injects the API token server-side from
// WEB_BFF_API_TOKEN. The browser never holds or sends a token, and no rewrite
// forwards raw client requests anymore. API_INTERNAL_URL is still the
// server-side upstream for that handler.
const nextConfig = {};

export default nextConfig;
