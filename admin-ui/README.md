# SNS Admin UI (React)

Authenticated, **localhost-only** administration panel (spec §31–33). Built as a static
SPA and served by the `sns-admin` backend over `127.0.0.1`. Not exposed publicly by default.

## Sections (spec §31)

Dashboard · Device Information · Activity Timeline · Browser Activity · Screenshots ·
System Events · Storage · Health · Configuration · Audit Logs · Integrity Verification.

## API

Consumes the `sns-admin` routes (see `crates/sns-admin/src/routes.rs`). All requests carry
the session cookie issued by `POST /api/login`; mutations carry a CSRF token. Screenshots
are fetched via `GET /api/screenshots/:id/image`, which decrypts **on demand** server-side
and streams bytes — decrypted content is never written to disk, and each view is audited
(spec §33).

## Status

Scaffold. The component tree + Vite build config land with the `sns-admin` HTTP server
(BUILD-STATUS.md, step 14). Stack: React + Vite + TypeScript, no external CDN (bundled).
