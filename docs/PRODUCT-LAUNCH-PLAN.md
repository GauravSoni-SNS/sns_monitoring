# PRODUCT-LAUNCH-PLAN.md — SNS Endpoint Security (go-to-market)

Turning the working system into a sellable product. Current state: Windows agent + multi-tenant
central server + dashboard, all functional and verified. This plan covers what's required before
charging customers, in priority order.

## OS support (reality)
- **Agent: Windows only** (10/11/Server, x64). Deep Win32 use (capture, USB, UIA, registry,
  spooler, DPAPI, Service). macOS/Linux agents = separate native builds, each a large project —
  defer to post-launch, build on demand.
- **Server + dashboard: OS-independent.** Server runs on any Linux/Windows/cloud host; the boss
  views the dashboard from any browser / phone.
- **Launch stance:** Windows-first. Most corporate endpoints are Windows; this covers the market
  while keeping scope realistic.

## Phase E — Productization (launch-ready). Ordered.

### E1. Trustable install (MUST)
- **Code-sign** every exe + installer with an **EV / OV code-signing certificate** → no Windows
  SmartScreen / antivirus blocks on customer machines. (Without this, deployment fails in the real
  world.)
- **MSI installer** (WiX) instead of the zip: Add/Remove Programs entry, clean upgrade/downgrade,
  **silent/mass deploy via GPO or Intune** (`msiexec /i sns.msi /qn SYSTEMNAME=… ENROLL=…`).
- **Auto-update**: agent checks the server for a newer signed build and self-updates.

### E2. Central screenshots (core value — D.2b)
- Agent re-encrypts each screenshot under an **org public key** (boss holds the private key) and
  uploads the blob to object storage (S3-compatible). Dashboard decrypts for the boss only.
- Server never sees plaintext or the device's local key — keeps the security promise.

### E3. Self-serve accounts + licensing (to actually sell)
- **Org signup** on the server (business creates account, gets enroll token + agent download).
- **Per-seat licensing**: license keys, seat count enforcement, trial period, expiry.
- Billing hook (Stripe or manual invoicing to start).

### E4. Hosted server + ops
- Deploy `sns-server` behind **TLS** (Caddy/Nginx) on a cloud host with a domain.
- **Backups** (Postgres + blob store), monitoring, log rotation, rate limiting.
- Scale path: connection pooling (done via Neon), move admin sessions to Redis for multi-instance.

### E5. Legal / compliance (MANDATORY for a monitoring product)
- **Disclosed-monitoring consent**: employee acknowledgement flow; the agent already assumes a
  disclosed policy — productize the consent record.
- **EULA, Privacy Policy, DPA**; data-retention terms; lawful-basis docs (India **DPDP Act**, and
  **GDPR** if any EU users).
- Note: the owner operates a legal practice (soniandsoni.legal) — well placed to lead this.

### E6. Tamper resistance / hardening
- **Tamper alert**: if the service is stopped/disabled or the agent uninstalled without authority,
  raise an alert (and sync it) so the boss sees evasion attempts.
- Protect the device token at rest (DPAPI-wrap it like the data key).
- Service recovery (auto-restart on failure) + "protected" install dir ACLs (already partial).

### E7. QA, docs, support
- Multi-PC pilot (10–50 machines), performance + DB load testing.
- Admin deployment guide, agent install guide, troubleshooting, runbook (partly written).
- Support channel + versioned release notes.

### E8. Branding / GTM
- Product name, logo, one-page site, pricing tiers (e.g. per-seat/month), demo org.

## Suggested MVP-to-GA cut
**MVP to start selling:** E1 (signed MSI) + E2 (central screenshots) + E3 (licensing/signup) +
E4 (hosted TLS server) + E5 (legal docs). E6/E7/E8 harden and polish in parallel / fast-follow.

## Recommended next build step
**E1 (signed MSI installer + auto-update)** — nothing deploys cleanly to customers without it, and
it unblocks the pilot. Then **E2 central screenshots**. Code-signing needs a purchased certificate
(EV ~$250–600/yr) — a procurement step the owner does; the MSI + auto-update are buildable now.
