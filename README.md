# Cloudflare L7 Best Practices Repository

A searchable repository of security, performance, and reliability best practices for Cloudflare application (Layer 7) services, built on Cloudflare Workers and D1.

## Features

- Instant search with highlighting, filters, sortable columns, expandable details, and permalinks (`/#practice-<id>`)
- Shareable views: search, filter, and sort state is kept in the URL
- Responsive: sticky toolbar and table header on desktop, cards on phones, light/dark themes
- Dashboard to add entries, protected by Cloudflare Access

## Architecture

| Layer         | Implementation                                                                                                                                                                                                                              |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend      | Vanilla HTML/CSS/JS in [`public/`](public/), served by [Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/) (free, does not invoke the Worker)                                                                 |
| API           | Worker in [`src/index.js`](src/index.js), runs only for `/api/*` and `/dashboard/api/*`                                                                                                                                                     |
| Read caching  | [Workers Cache](https://developers.cloudflare.com/workers/cache/) on the `PublicReads` entrypoint: cache hits skip Worker code and D1; writes purge by tag                                                                                  |
| Database      | [D1](https://developers.cloudflare.com/d1/) with [migrations](migrations/) and the [Sessions API](https://developers.cloudflare.com/d1/best-practices/read-replication/)                                                                    |
| Auth          | [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) on `/dashboard`; the Worker also validates the Access JWT on writes                                                                                  |
| Observability | Workers Logs, Traces, and [Issues](https://developers.cloudflare.com/workers/observability/issues/) (error monitoring); [Local Explorer](https://developers.cloudflare.com/workers/local-development/local-explorer/) during `wrangler dev` |

Workers Cache is enabled per entrypoint ([`wrangler.jsonc`](wrangler.jsonc)), not Worker-wide: enabling it on the default entrypoint would bill static asset requests, which are otherwise free ([pricing](https://developers.cloudflare.com/workers/cache/#pricing)).

## Getting Started

```bash
npm install
npx wrangler d1 create D1_DB_L7_BEST_PRACTICES --location weur   # once, if the database does not exist
./create_d1_schema.sh --local --seed                              # local schema + seed data
cp .dev.vars.example .dev.vars                                    # allow dashboard writes on localhost
npm run dev
```

Test and deploy:

```bash
npm test
./create_d1_schema.sh --remote   # apply pending migrations (idempotent)
npm run deploy
```

After changing bindings in `wrangler.jsonc`, run `npm run cf-typegen`.

## API

| Endpoint                        | Description                                                                                     |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| `GET /api/practices`            | All practices. Optional filters: `search`, `categoryId`, `featureId`, `area`, `level`, `impact` |
| `GET /api/categories`           | Categories                                                                                      |
| `GET /api/features`             | Cloudflare features                                                                             |
| `POST /dashboard/api/practices` | Create a practice (Access-protected, JSON body)                                                 |

## Search engines and AI crawlers

This site opts out of indexing and AI use:

- Every response sends `X-Robots-Tag: noindex, nofollow` (HTML pages also include a robots meta tag).
- [`robots.txt`](public/robots.txt) sets [Content Signals](https://contentsignals.org/) `search=no, ai-input=no, ai-train=no`, blocks known AI crawlers, and disallows `/api/`, `/dashboard`, and [`/cdn-cgi/`](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/).
- `robots.txt` is voluntary. To enforce blocking, use [AI Crawl Control](https://developers.cloudflare.com/ai-crawl-control/) on the zone.

## Production settings (dashboard)

- Optional: enable [D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) for faster cache misses.
- HSTS and AI crawler blocking are zone settings, not part of this repository.

## Contributing

Pull requests with new best practices or improvements are welcome. Content updates are re-runnable SQL files in [`data/`](data/). Allowed users can also add entries through the dashboard.

## Disclaimer

This is a personal project for educational and informational purposes only. It is not an official Cloudflare product, and its content does not represent official Cloudflare guidance or the views of the author's employer.

The recorded best practices are provided "as is", without warranty of any kind. They may be incomplete, outdated, or unsuitable for your environment, plan, or compliance requirements. Always validate them against the [official Cloudflare documentation](https://developers.cloudflare.com/) and test changes (for example, with the _Log_ action) before applying them in production.

The author and contributors are not responsible or liable for any damage, outage, security incident, data loss, or other consequence arising from the use of, or reliance on, any information in this repository or on the website. You use it at your own risk.

Cloudflare and related marks are trademarks of Cloudflare, Inc.
