import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) { return twMerge(clsx(inputs)); }

export function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}

// The locale is named rather than left to the browser: the UI ships English, and an
// unpinned formatter renders the same count as `1,234`, `1 234` or `١٢٣٤` depending
// on the reader's settings — which is a different string in a screenshot, a report
// and a support thread. `scripts`-style gates cannot see this; timezoneContract.test
// asserts it.
export function formatNumber(n: number): string { return new Intl.NumberFormat("en-US").format(n); }
