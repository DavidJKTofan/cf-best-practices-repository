# Authentication for Cloudflare L7 Best Practices

Public reading, searching, Markdown retrieval, and API discovery require **no authentication or agent registration**. Do not send credentials to public read endpoints.

Start with [the agent index](/llms.txt), [API documentation](/api-docs), or [OpenAPI](/openapi.json).

## Dashboard writes

The dashboard at `/dashboard` and write endpoint `POST /dashboard/api/practices` require the owner's Cloudflare Access authorization. The Worker validates the Access JWT assertion supplied by Access. Automated public readers should use the anonymous read API instead.

Writes require `Content-Type: application/json`, a body of at most **64 KiB of UTF-8 bytes**, and an `Idempotency-Key` header containing 16–128 letters, digits, hyphens, or underscores (a random UUID is recommended). Reuse the same key and practice data when retrying an uncertain save. Keys are scoped to the verified Access identity (user subject or signed service-token identity); replay returns the original `201` response and ID. Reusing a completed key with different normalized data returns `409`. Validation failures do not consume the key. Do not send write credentials or keys to the public read API.

The dashboard retains the retry key in this tab's session storage, including across reloads; it does not store form contents or credentials. When storage is unavailable, retry protection survives only while the page stays open. A confirmed save clears the key. Resetting an uncertain submission requires confirmation because a new key can create another practice. Cache invalidation is attempted after every successful save/replay, but browser caches and a failed purge can delay public visibility.

This application does not operate an OAuth authorization server, issue agent credentials, or offer self-service registration. Ask the repository owner for dashboard access if you need to contribute. Cloudflare Access policy is configured separately from this public read interface.
