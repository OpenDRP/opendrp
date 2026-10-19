/**
 * Client-side mirror of the asset rules the API enforces (WI-14, WI-19).
 *
 * Presentation only: the backend still decides. It exists so an operator learns
 * that a value is wrong before sending it, and so a `422` that does get through
 * can be shown next to the field it is about instead of as one opaque sentence.
 *
 * The mirror is deliberately *looser* than the server in every direction: a rule
 * the client gets wrong could otherwise refuse input the API would accept, which
 * is worse than sending a request that comes back with a real reason.
 */

/**
 * The type the API will assign to a value promoted from an observation.
 *
 * Mirrors ``promote_observation_to_asset``: a value that parses as an address
 * becomes ``ip_address``, anything else becomes ``domain``.
 */
export function promotedAssetType(value: string): "ip_address" | "domain" {
  const trimmed = value.trim();
  // IPv6 literals and IPv4 dotted quads; the backend uses ipaddress.ip_address,
  // which accepts both forms and nothing else this rule has to recognize.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed) || trimmed.includes(":")) {
    return "ip_address";
  }
  return "domain";
}

/** The criticality a promoted asset gets: the API default, not an observation's. */
export const PROMOTED_ASSET_CRITICALITY = "medium";

/** The same bound the API applies to a keyword (`schema.KEYWORD_MAX_LENGTH`). */
export const KEYWORD_MAX_LENGTH = 200;

const HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const KEYWORD_FORBIDDEN_RE = /["\\\u0000-\u001f]/;

function validIpv4(value: string): boolean {
  const match = IPV4_RE.exec(value);
  if (!match) return false;
  return match.slice(1, 5).every((octet) => Number(octet) <= 255);
}

function validIpv6(value: string): boolean {
  // A shape check only: the browser has no IPv6 parser, and the API has one.
  // Accepting anything colon-shaped here means the server still decides, and a
  // value it rejects comes back as a per-field 422.
  return IPV6_RE.test(value) && (value.match(/::/g) ?? []).length <= 1;
}

/**
 * The reason a value cannot be used for its type, or ``null`` when it looks fine.
 *
 * Mirrors ``validate_and_normalize_asset_value`` in the API; the wording is the
 * same where it can be, because an operator comparing the two should not have to
 * work out that they mean the same thing.
 */
export function validateAssetValue(assetType: string, value: string): string | null {
  const raw = value.trim();
  if (assetType === "domain") {
    if (!raw) return "Invalid domain format";
    const lowered = raw.replace(/\.+$/, "").toLowerCase();
    let ascii = lowered;
    try {
      // IDNA, the same conversion the API performs before matching the FQDN
      // pattern: a Unicode domain is valid input, not a typo.
      ascii = new URL(`http://${lowered}`).hostname;
    } catch {
      return "Invalid domain format";
    }
    return HOSTNAME_RE.test(ascii) ? null : "Invalid domain format";
  }
  if (assetType === "ip_address") {
    if (!raw) return "Invalid IP address format";
    return validIpv4(raw) || validIpv6(raw) ? null : "Invalid IP address format";
  }
  if (assetType === "email_account") {
    if (!raw) return "Invalid email format";
    return EMAIL_RE.test(raw) ? null : "Invalid email format";
  }
  if (assetType === "keyword_domain" || assetType === "keyword_title") {
    if (!raw) return "Keyword cannot be empty";
    if (raw.length > KEYWORD_MAX_LENGTH) {
      return `A keyword must be at most ${KEYWORD_MAX_LENGTH} characters`;
    }
    if (KEYWORD_FORBIDDEN_RE.test(raw)) {
      return "A keyword cannot contain quotes, backslashes or control characters";
    }
    return null;
  }
  return null;
}

/**
 * Per-field reasons from a Pydantic/FastAPI `422`, keyed by field name.
 *
 * The API answers a bad body with a list of `{loc, msg}` entries. Shown as one
 * flattened sentence, a two-field error reads as one problem the operator has to
 * guess at; mapped back to fields, each message sits where the fix is.
 */
export function fieldErrorsFromApiError(error: unknown): Record<string, string> {
  const response = error as { response?: { data?: { detail?: unknown } } } | undefined;
  const detail = response?.response?.data?.detail;
  if (!Array.isArray(detail)) return {};

  const fields: Record<string, string> = {};
  for (const entry of detail) {
    if (!entry || typeof entry !== "object") continue;
    const { loc, msg } = entry as { loc?: unknown; msg?: unknown };
    if (!Array.isArray(loc) || typeof msg !== "string") continue;
    const field = [...loc].reverse().find((part) => typeof part === "string");
    if (typeof field === "string" && !(field in fields)) fields[field] = msg;
  }
  return fields;
}
