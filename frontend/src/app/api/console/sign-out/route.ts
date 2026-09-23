import { NextResponse } from "next/server";

import { SESSION_COOKIE } from "@/lib/session-cookie";

/**
 * Discard the session and return to the sign-in page.
 *
 * This exists as a route handler because Next.js only allows cookies to be
 * modified in a server action or a route handler, never in a server component.
 * A layout that discovers the session is unusable therefore redirects here
 * rather than trying to clear the cookie itself.
 *
 * The `Location` header is relative on purpose. Building an absolute URL from
 * `request.url` would use the address the server is bound to, which inside a
 * container is `0.0.0.0` rather than the host the operator actually typed.
 */
export const dynamic = "force-dynamic";

/** Handle `GET /api/console/sign-out`. */
export function GET(): NextResponse {
  const response = new NextResponse(null, {
    // 303: the session changed, and the browser should follow with a GET.
    status: 303,
    headers: { Location: "/login", "Cache-Control": "no-store" },
  });
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
