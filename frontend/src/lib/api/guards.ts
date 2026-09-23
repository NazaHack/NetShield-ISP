import "server-only";

import { notFound } from "next/navigation";

import { getCurrentUser } from "@/lib/api/console";
import type { User } from "@/lib/api/types";

/**
 * Page-level authorisation guards.
 *
 * These decide what a page renders, not what a caller may do: the API performs
 * its own authorisation on every request, and that is the boundary. What the
 * guards add is the right *response*. Without one, a tenant user opening an
 * administrator URL gets a 500 from the first refused call, which is both
 * confusing and a hint that the page exists.
 */

/**
 * Require a platform administrator, or render the not-found page.
 *
 * A 404 rather than a 403: the existence of the administration section is not
 * something a tenant user needs confirmed.
 *
 * @returns The signed-in administrator.
 */
export async function requirePlatformAdmin(): Promise<User> {
  const user = await getCurrentUser();
  if (user.role !== "PLATFORM_ADMIN") {
    notFound();
  }
  return user;
}
