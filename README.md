# Cloudflare Field Guide

Unofficial, sourced Cloudflare recommendations and implementation patterns, built with Astro, Cloudflare Workers and D1.

[Browse the guide](https://db.automatic-demo.com) · [API documentation](https://db.automatic-demo.com/api-docs) · [Project docs & production status](docs/README.md)

## Features

- Server-rendered search, filters and paginated results, usable without JavaScript.
- Stable practice URLs with prerequisites, configuration examples, sources and freshness information.
- Compact light/dark UI, labeled Domain colors and neutral Level badges.
- HTML, Markdown and JSON reads, with OpenAPI and agent discovery.
- Access-protected contributions and a role-gated editorial workflow; live native publication requires separate approval.

Markdown reading links and all footer links open safely in new tabs. Ordinary navigation stays in the current tab.

## Local development

Requires **Node 22.23.4+**; offline content/release checks also use **Python 3**.

```bash
npm ci
./create_d1_schema.sh --local --seed
cp .dev.vars.example .dev.vars  # optional: enable local dashboard writes
npm run dev
```

Seed only an empty local database. Local development must not use a remote D1 binding. For forks, deployment setup and disposable previews, see [the project docs](docs/README.md#development-and-deployment).

## Checks

```bash
npm test -- --run
npm run typecheck
npm run content:check
npm run release:check
npx wrangler types --check
npm run frontend:check
npm run build
npm run frontend:test
npm run deploy:check  # dry run only; uses the generated Astro configuration
```

Deployment and remote data changes require explicit approval; follow the [release runbook](docs/phase6/rehearsal-and-rollout.md). Current verification limits are recorded in [docs/README.md](docs/README.md#production-checkpoint--2026-11-11).

## Contributing

Improvements and sourced practices are welcome. Read [AGENTS.md](AGENTS.md) for code, content, security and verification rules, and the [documentation index](docs/README.md) for architecture and editorial contracts. Keep both READMEs and AGENTS.md current when behavior or setup changes.

## Disclaimer

This is a personal educational project, not an official Cloudflare product or guidance, and is not affiliated with or endorsed by Cloudflare. Its content does not represent the views of the author's employer. Cloudflare and related marks belong to Cloudflare, Inc.

Guidance is provided **AS IS, without warranty** and may be incomplete, outdated or unsuitable for your environment. Validate official sources, plan entitlements and observed behavior before enforcement. The author and contributors accept no liability for damage, outages, security incidents, data loss or other consequences. Use at your own risk.

```text
THIS SOFTWARE IS PROVIDED BY CLOUDFLARE "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CLOUDFLARE BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
