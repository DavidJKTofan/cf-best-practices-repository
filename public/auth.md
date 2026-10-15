# Authentication for Cloudflare L7 Best Practices

Public reading, searching, Markdown retrieval, and API discovery require **no authentication or agent registration**. Do not send credentials to public read endpoints.

Start with [the agent index](/llms.txt), [API documentation](/api-docs), or [OpenAPI](/openapi.json).

## Dashboard writes

The dashboard at `/dashboard` and write endpoint `POST /dashboard/api/practices` require the owner's Cloudflare Access authorization. The Worker validates the Access JWT assertion supplied by Access. Automated public readers should use the anonymous read API instead.

This application does not operate an OAuth authorization server, issue agent credentials, or offer self-service registration. Ask the repository owner for dashboard access if you need to contribute. Cloudflare Access policy is configured separately from this public read interface.
