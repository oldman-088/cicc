/** @type {import('next').NextConfig} */

// Server-side proxy target for the operations API. The browser only ever
// calls relative "/api/..." URLs; Next.js rewrites forward them here.
const apiInternalUrl = process.env.API_INTERNAL_URL || "http://127.0.0.1:8000";

const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${apiInternalUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
