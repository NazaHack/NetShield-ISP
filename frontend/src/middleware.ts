import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE } from "@/lib/session-cookie";

/**
 * Session gate.
 *
 * Without a session cookie every console route redirects to the sign-in page.
 * This is a convenience rather than the security boundary: the real check is
 * that every API call carries the operator's token, and the API rejects an
 * absent or expired one. The middleware exists so an operator gets a sign-in
 * form instead of a page full of errors.
 */
export function middleware(request: NextRequest): NextResponse {
  const hasSession = Boolean(request.cookies.get(SESSION_COOKIE)?.value);
  const { pathname } = request.nextUrl;

  if (!hasSession && pathname !== "/login") {
    const target = new URL("/login", request.url);
    return NextResponse.redirect(target);
  }

  if (hasSession && pathname === "/login") {
    return NextResponse.redirect(new URL("/", request.url));
  }

  return NextResponse.next();
}

export const config = {
  // Page routes only.
  //
  // `/api/console/*` is deliberately excluded: those handlers are called by
  // `fetch` from the browser and perform their own session check, returning a
  // 401. Redirecting them to the sign-in page would hand the caller an HTML
  // document where it expected JSON.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api/).*)"],
};
