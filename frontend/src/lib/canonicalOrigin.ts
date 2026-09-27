/** Return a safe same-path URL on the configured canonical origin, or null. */
export function canonicalNavigationUrl(
  current: Pick<Location, "origin" | "pathname" | "search" | "hash">,
  canonicalOrigin: string,
): string | null {
  const target = canonicalOrigin.trim().replace(/\/$/, "");
  if (!target || current.origin === target) return null;
  try {
    const parsed = new URL(target);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    if (parsed.username || parsed.password || parsed.pathname !== "/") return null;
    return `${parsed.origin}${current.pathname}${current.search}${current.hash}`;
  } catch {
    return null;
  }
}
