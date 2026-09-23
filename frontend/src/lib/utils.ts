import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merge Tailwind class names, resolving conflicts in favour of the last value.
 *
 * Required by every shadcn/ui component: it lets a caller override a variant's
 * built-in classes without the two rules fighting over specificity.
 *
 * @param inputs - Class values, including conditionals and arrays.
 * @returns A single deduplicated class string.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
