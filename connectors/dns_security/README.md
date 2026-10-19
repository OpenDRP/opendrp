# DNS Security connector workers

This image contains six independently provisioned workers for the `dns`
module: `dns-rdap`, `dns-resolver`, `dns-ctlogs`, `dns-tlsprobe`, `dns-virustotal`
and `dns-shodan`. Each worker
uses its own connector token and reads active `domain` assets — `dns-shodan` also
reads active `ip_address` assets, because it asks the index about our own
addresses as well as their names. It submits
normalized observations through the connector API; it has no database or Redis
credentials.

## Connect and configure

Follow the [DNS Security operator guide](../../docs/dns-security.md#connect-the-workers)
for exact per-worker token commands, `.env` variables, selective Compose startup,
health verification and rotation. The module id is `dns` (the former `dns_security`
stays accepted as a transitional alias). RDAP, resolver, CT Logs and the TLS probe
start with
the installation; VirusTotal is gated by the `virustotal` Compose profile and
`dns-shodan` by `shodan`, which the phishing Shodan worker shares.
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
- **TLS probe** opens one bounded handshake per active asset and allowlisted port
  (`DNS_SECURITY_TLS_PORTS`, default `443`, at most three; `DNS_SECURITY_TLS_PATH`
  is the request path) and stores the certificate the service actually serves,
  with its chain, validity, serial, SPKI hash and SAN names. It reads our own
  assets only, sends no traffic to a third party, and stops at
  `DNS_SECURITY_TLS_MAX_PROBES` handshakes with `probe_budget_reached`. A refused
  or failed handshake is evidence about the probe, never about the certificate,
  and a served-certificate expiry reminder needs a fresh successful handshake.
- **Shodan** asks the index what each of our own addresses serves — the free
  `GET /shodan/host/{ip}` lookup, whose answer confirms the certificate our probe
  read and adds the organisation, ASN, JARM, page title and favicon hash the
  certificate rules score on — and, per certificate this scan just found, a
  `GET /shodan/host/search` for `ssl.cert.fingerprint` that answers where *else*
  it is being served. The reverse search spends one query credit per request, so
  it is capped per scan by the `max_searches` connector setting (default 1; `0`
  keeps the free half) and reserved against the approved source account before it
  is sent. Provider data only: no request is ever sent to an address the provider
  reported. The SHA-1 fingerprint is the search key — Shodan accepts the
  SHA-256 spelling and matches nothing — and `test_shodan_dns.py` pins that.
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
