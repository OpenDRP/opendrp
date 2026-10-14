# DNS Security connector workers

This image contains four independently provisioned workers for the `dns`
module: `dns-rdap`, `dns-resolver`, `dns-ctlogs`, and `dns-virustotal`. Each worker
uses its own connector token and reads only active `domain` assets. It submits
normalized observations through the connector API; it has no database or Redis
credentials.

## Connect and configure

Follow the [DNS Security operator guide](../../docs/dns-security.md#connect-the-workers)
for exact per-worker token commands, `.env` variables, selective Compose startup,
health verification and rotation. The module id is `dns` (the former `dns_security`
stays accepted as a transitional alias). RDAP, resolver and CT Logs start with
the installation; only VirusTotal is gated by the `virustotal` Compose profile.
The standard setup wizard does not yet select these workers. Configure and start only intended sources: starting a worker may
immediately execute previously queued jobs. Worker core tokens are not provider
API keys, and a container restart does not apply environment changes.

## Sources and evidence

- **RDAP** reads registration and expiration events from the RDAP bootstrap
  service. Expiration events are parsed into `expires_at` for the 30/14/7/1-day
  reminder workflow. Bootstrap redirects are bounded, HTTPS-only and public-IP
  pinned; unsafe destinations are rejected.
- **DNS resolver** asks for A, AAAA, and CNAME records. NS, MX, and CAA can be
  enabled with `DNS_SECURITY_RESOLVER_EXTENDED=true`. TTL is reported as metadata
  and is *not* a domain-registration expiry alert. Each submitted row contains
  a bounded complete RRset rather than overwriting individual addresses.
- **CT Logs** reads paginated certificate-transparency records from
  `https://api.ctlogs.dev`. These are explicitly marked historical; a certificate
  appearance does not prove current DNS or ownership. Optional Bearer
  authentication reads `DNS_SECURITY_CTLOGS_API_TOKEN`. Wildcards retain their
  scope and are not promotable as concrete hostname assets. The anonymous API limit is
  100 requests/hour, one at a time, up to 10 pages. Requests (including retries)
  are paced at 36 seconds and bounded to 100 per scan. Current host/DNS endpoints
  may be considered separately; certificate records remain historical evidence.
- **VirusTotal** reads the public API v3 subdomain and resolution endpoints. It
  is disabled unless both `DNS_SECURITY_VT_API_KEY` and
  `DNS_SECURITY_VT_PUBLIC_NONCOMMERCIAL=true` are set. The public API is limited
  to personal, non-commercial use; commercial/business users must not enable this
  connector with a public-tier key. Responses retain passive-DNS dates and
  originating hosts; next-page URLs must match the original HTTPS endpoint.
  Shared Redis quota reservation fails closed
  and is performed before every outgoing request attempt, including retries,
  against the provider budget the operator approved for the account (VirusTotal
  publishes 4 requests per minute and 500 per day for its public API, and the
  worker stops a single scan at 500 requests). A licensed, quota-appropriate integration
  for commercial use must be assessed separately.

No provider key belongs in source code, fixtures, logs, module definitions, or
committed environment examples. Provide keys only through the matching worker's
runtime environment/secret management. Do not enable VirusTotal with the public
key as a substitute for a commercial license.

Observations are source-scoped mutable inventory. Repeated current DNS/RDAP facts
refresh in place; certificate and subdomain historical evidence remains
independent. A failed provider run does not delete previously stored facts or
another source's results. DNS observations can be promoted into the monitored
asset inventory, but certificate evidence alone does not establish that an
organization owns the subject.
