/**
 * Next.js configuration for the NetShield-ISP dashboard.
 *
 * `output: "standalone"` produces a self-contained server bundle, which is what
 * the production Docker stage copies into a minimal runtime image.
 *
 * The security headers mirror the ones the API applies. The dashboard renders
 * untrusted content — hostnames, service banners and Nmap script output taken
 * from scanned networks — so a strict Content-Security-Policy is a hard
 * requirement rather than a nicety.
 *
 * @type {import("next").NextConfig}
 */
const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,

  eslint: {
    dirs: ["src"],
  },

  async headers() {
    const isDevelopment = process.env.NODE_ENV !== "production";

    // The dev server needs eval for React Fast Refresh; production does not.
    const scriptSrc = isDevelopment
      ? "'self' 'unsafe-inline' 'unsafe-eval'"
      : "'self' 'unsafe-inline'";

    const apiOrigin = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

    const contentSecurityPolicy = [
      "default-src 'self'",
      `script-src ${scriptSrc}`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      `connect-src 'self' ${apiOrigin}${isDevelopment ? " ws: wss:" : ""}`,
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
    ].join("; ");

    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: contentSecurityPolicy },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "geolocation=(), microphone=(), camera=()",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
