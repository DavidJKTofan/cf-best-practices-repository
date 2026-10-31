# auth.md — Authentication for Cloudflare Field Guide

Public reading, searching, Markdown retrieval, and API discovery require **no authentication or agent registration**. Do not send credentials to public read endpoints.

Start with [the agent index](/llms.txt), [API documentation](/api-docs), or [OpenAPI](/openapi.json).

`/api/v2/entries`, `/api/v2/entries/{id}`, and `/api/v2/facets` are also anonymous, published-only reads. No query parameter enables draft/preview access. All writes remain under `/dashboard/api/*`, never `/api/v2/*`.

## Dashboard writes

The dashboard at `/dashboard` and write endpoint `POST /dashboard/api/practices` require the owner's Cloudflare Access authorization. The Worker validates the Access JWT assertion supplied by Access. Automated public readers should use the anonymous read API instead.

Writes require `Content-Type: application/json`, a body of at most **64 KiB of UTF-8 bytes**, and an `Idempotency-Key` header containing 16–128 letters, digits, hyphens, or underscores (a random UUID is recommended). Reuse the same key and practice data when retrying an uncertain save. Keys are scoped to the verified Access identity (user subject or signed service-token identity); replay returns the original `201` response and ID. Reusing a completed key with different normalized data returns `409`. Validation failures do not consume the key. Do not send write credentials or keys to the public read API.

The dashboard retains the retry key in this tab's session storage, including across reloads; it does not store form contents or credentials. When storage is unavailable, retry protection survives only while the page stays open. A confirmed save clears the key. Resetting an uncertain submission requires confirmation because a new key can create another practice. Cache invalidation is attempted after every successful save/replay, but browser caches and a failed purge can delay public visibility.

This application does not operate an OAuth authorization server, issue agent credentials, or offer self-service registration. Ask the repository owner for dashboard access if you need to contribute. Cloudflare Access policy is configured separately from this public read interface.

## Typed editorial workflow (explicit private roles required)

The `/dashboard/editorial` workbench uses the [protected editorial API schema](/openapi-editorial.json). A valid Access JWT alone is insufficient: private, owner-provisioned editor/reviewer/publisher grants are required. Unknown actors, including the local write bypass without a grant, are denied. Caller role headers and arbitrary JWT claims never confer a role.

- Editors reserve native IDs, save typed working copies and submit exact versions for independent review.
- A reviewer who has never contributed to the entry approves or requests changes. A non-contributing publisher may publish; the reviewer may also be that publisher. The reviewer must still hold their grant.
- Every mutation requires an `Idempotency-Key` and, except creation, `expectedVersion`. Every successful transition increments the version; changed data, stale versions/bases or invalid transitions return 409. Edit/rebase invalidates approval. Reuse the exact command/target/version/payload on uncertain retries.
- HTML/Markdown previews require an editorial role and are private/no-store/noindex, without public CORS. Public flags never expose them. Publication freezes metadata/body/sources/taxonomy and switches the pointer transactionally; success/replay attempts the public cache-owning purge.
- Publication requires recorded evidence, non-future editorial/fact dates, a future review-due date, and human review of public sources/applicability. Validation is not factual verification or a guarantee of deployment success.
- Deprecation/supersession are reviewed revisions, not deletes. Stable citations remain readable with status/replacement metadata. Legacy conversion is still blocked.

The workbench stores only an uncertain mutation's random key and SHA-256 payload signature in tab session storage, never draft content or credentials. Retry unchanged data in the open page. Reload recovery requires reconstructing the exact original content and expected version; do not assume the latest loaded version is the uncertain operation. Storage denial loses retry protection on reload. Private role grants, contributors, reviews and receipts are excluded from public catalog snapshots and must be retained in private recovery backups. Live Access paths and role provisioning remain separately approved release gates.
