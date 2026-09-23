import { cookies } from "next/headers";

/**
 * Operator session handling.
 *
 * The console talks to an API that authenticates with bearer tokens. Those
 * tokens are service credentials: an administrator token can create and delete
 * every tenant on the platform.
 *
 * It therefore never reaches the browser. The operator pastes it once, the
 * server stores it in an `httpOnly` cookie, and every request to the API is made
 * from the Next.js server with the cookie read server-side. A cross-site
 * scripting flaw in this console can make the browser act as the operator while
 * the session lasts, but it cannot read the credential and use it elsewhere.
 *
 * This module is server-only. Importing it from a client component is a build
 * error rather than a silent leak.
 */
import "server-only";

import { SESSION_COOKIE } from "@/lib/session-cookie";

/**
 * Maximum session length, independent of the token's own expiry.
 *
 * The API rejects an expired token anyway; this simply stops a stale cookie
 * lingering in a shared browser long after it is useful.
 */
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 12;

/** Read the operator's API token, or `null` when there is no session. */
export async function getSessionToken(): Promise<string | null> {
  const store = await cookies();
  const value = store.get(SESSION_COOKIE)?.value;
  return value && value.length > 0 ? value : null;
}

/**
 * Start a session.
 *
 * @param token - A bearer token already verified against the API.
 */
export async function setSessionToken(token: string): Promise<void> {
  const store = await cookies();
  store.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    // Set over HTTPS only in production. Requiring it in development would make
    // the cookie silently fail on http://localhost.
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_MAX_AGE_SECONDS,
  });
}

/** End the session. */
export async function clearSessionToken(): Promise<void> {
  const store = await cookies();
  store.delete(SESSION_COOKIE);
}

