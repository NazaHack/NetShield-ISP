/**
 * The session cookie's name, in a module of its own.
 *
 * Both the server-only session helpers and the Edge middleware need this value.
 * Keeping it here means the middleware never imports a module marked
 * `server-only`, which would pull `next/headers` into the Edge runtime where it
 * does not belong.
 */

/** Name of the cookie holding the operator's API token. */
export const SESSION_COOKIE = "netshield_session";
