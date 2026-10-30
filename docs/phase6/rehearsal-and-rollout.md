# Phase 6: rehearsal and approved rollout

**Status: local release-readiness tooling and approved private-copy rehearsal, not a rollout.** Owner directed Phase 6 development on 2026-10-30 after local Phases 0–5, then approved a fresh private production backup and local rehearsal while retaining release gates. The current copy now passes offline and isolated local D1/workerd checks; see the [2026-10-31 review](scalability-and-production-readiness.md). No staging resources, live roles, publication, deployment, remote database write or security-policy changes occurred. Exact-deployed-artifact rollback review, independent review and staging/live evidence remain outstanding. The [roadmap](../cloudflare-platform-roadmap.md) is the checkpoint. **Phase 6's live exit gate remains open.**

## Tools and boundaries

| Command                                                              | Purpose                                                              | Does not establish                                              |
| -------------------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------- |
| `npm run release:check`                                              | Credential-free synthetic rehearsal/config/HTTP-probe tests          | Production-copy provenance or live behavior                     |
| `npm run release:rehearse -- …`                                      | Offline SQLite rehearsal of an approved full private export          | workerd/runtime, live Access/cache, or release approval         |
| `CF_STAGING_CONFIG=/private/path/wrangler.json npm run build`        | Validate isolated configuration, build into `dist-staging/`          | Provisioning, deployment, or actual Access protection           |
| `npm run release:staging:check -- dist-staging/server/wrangler.json` | Check generated targets, cache/assets and public artifacts           | Account state or policy coverage                                |
| `npm run release:smoke -- --base https://approved.example.com`       | Anonymous, bounded GET/HEAD/OPTIONS on an explicitly approved target | Authenticated mutations/retries/purges or browser certification |

No new tool calls Cloudflare's management API, provisions resources, grants roles, deploys, sends HTTP writes, or refreshes `initial_data.sql`. Smoke reads still contact the supplied host and can incur normal request costs. CI runs synthetic checks and a built-Worker probe journey only, never the live CLI or a private export. Production source configuration, migrations, content/seed, legacy creation SQL/hash namespace and owner-approved security/crawler policies are unchanged. Normal builds still produce `dist/`; the staging switch is opt-in. Existing unofficial/AS IS/no-warranty/liability notices remain in the README.

## 1. Review and scoped approval

Before any remote operation, record privately:

- Independent review of Phases 2–5 schema/allocation, publication/authorization, adapter/header/cache, source claims and runbook compatibility. Local tests are not independent review.
- Exact artifact/source revision and reviewed dependency remediation or owner-accepted disposition. Initial Phase 6 audits reported **7 findings (4 moderate, 3 high)**, including **3 (2 moderate, 1 high)** with `--omit=dev`. Subsequent [targeted local hardening](development-hardening.md) refreshes patched Wrangler/Vitest/plugin tooling without framework-major changes: root and isolated proof now return **0 findings and exit 0** for full and production-only audits. Independently review the changed lockfiles and re-audit before release; this is not a guarantee of security or a claim about deployed exploitability.
- Separately approved staging Worker/database/hostname/Access application/policies, then separately approved production changes. Inspect target configuration with read-only management tools before proposing mutations. Keep live expressions, identities, audiences, inventories and telemetry private.
- Recovery owner, tested compatible artifact, write/reconciliation window, protected backup location, copy freshness/provenance and a private pre-mutation Time Travel bookmark. A bookmark is not permission to restore; a Worker rollback does not roll back D1.

Private export, staging provisioning, Access/zone changes, each remote D1 change, deployment, editorial grants, publication and recovery are distinct approvals. Successful tests grant none of them. Obtain renewed approval when scope, inputs or targets change.

## 2. Current private-copy rehearsal

Keep full exports, allocator captures, working databases and recovery records **outside the repository**, with restrictive permissions. A public seed—even with synthetic receipts—is not a recovery copy. Full backups retain `PracticeCreations`, drafts, all revisions/publications, every `Editorial*` table, contributors/reviewers/grants, migration ledger and allocator high-water marks.

After export/read approval, capture D1 and allocator state consistently using the explicitly reviewed target config. Reconcile/repeat captures if concurrent writes make them inconsistent. These are **operator examples, not blanket permission**; the later approved production-read/export rehearsal is recorded separately:

```bash
npx wrangler d1 export DB --config /private/reviewed-target/wrangler.json --remote --output=/private/approved-copy/full.sql
npx wrangler d1 execute DB --config /private/reviewed-target/wrangler.json --remote --command='SELECT name, seq FROM sqlite_sequence ORDER BY name'
```

Save the allocator read privately as a JSON object mapping **every AUTOINCREMENT table** to its integer sequence, including zero for unused tables. Include deleted-ID high-water marks, not just `MAX(id)`, and the migration ledger's allocator if it uses AUTOINCREMENT. The runner rejects missing/extra names, invalid values and captures older than the export. It restores a higher captured floor when a dump omitted it. It cannot prove that an operator supplied a fresh, consistent, authorized capture.

Independently verify the applied schema baseline: `5` means through `0005`, `6` through `0006`, `7` through `0007`. Production tables predate migrations; inspect actual schema/ledger. The runner checks required columns, baseline indexes/triggers/views and ledger contradictions, and refuses unsupported/partial baselines. Known original-table constraint differences still need human/workerd review; this is not complete schema-equivalence certification.

```bash
npm run release:rehearse -- \
  --source /private/approved-copy/full.sql \
  --sequences /private/approved-copy/sequences.json \
  --baseline 5 \
  --output-dir /private/NEW-rehearsal-directory
```

The runner exclusively creates a new directory (0700; files 0600), never overwrites/reuses one, and never mutates inputs or normal `.wrangler/state`. It imports SQL with filesystem escapes disabled, checks SQLite/FK integrity, restores captured sequences, applies pending migrations and compares every pre-existing application/private table's original columns/rows. Only derived `sqlite_stat1`/`sqlite_stat4` are excluded; allocator floors are checked separately. It applies the four ordinary active patches twice with distinct clocks, verifies IDs/private state/allocator floors and current published-only export parity. **It never loads pilots or `local-starters.sql`.**

Old-app **SQL** probes run on a disposable branch: reserve/delete a native ID, use the unchanged legacy insert/receipt shape, recover an unchanged replay and force a later FK failure to prove transaction/receipt/sequence rollback. Full SQLite backup/recovery is compared including private state and allocators, then probed again. This is **not execution of the old Worker** or authenticated replay of unknown real caller keys.

Outputs are private: `rehearsal.sqlite` (upgraded copy without probe rows), `result.json` (scope/checks/remaining gates), and `provenance.json` (input/code digests to bind to the approval record). Digests do not establish freshness/approval. The SQLite file is not a Wrangler state directory or a public seed. On failure, the partial database and `failure.txt` remain private; the CLI exits nonzero without printing raw SQL/identities. Diagnose partial effects before using a **new** directory; never blindly retry remotely.

Next import the approved export into **separate local workerd/D1** storage, explicitly using `--local --persist-to=/private/new-state` and a reviewed config with no remote development bindings. Inspect the ledger and apply migrations/patches there. Execute the actual prior app's write/replay/conflict and current app's public/private/editorial journeys against that retained state; compare receipts, sources, pointers and allocators. Record import/runtime limitations. The offline runner alone does not close this gate.

## 3. Isolated staging and Access

Approve/provision staging separately. Do not upload a full private production backup to a public staging service. Use approved synthetic/public catalog data for externally reachable staging unless a separate data-handling/privacy review permits otherwise.

Prepare a **private strict-JSON** Wrangler source config outside this checkout. Copy the source configuration's date/flags, scoped assets, named exports, observability and limiter settings; explicitly replace:

- Worker/database names with distinct `*-staging` names; D1 with an already provisioned distinct nonzero UUID, never omitted for auto-provisioning.
- One exact staging custom domain; no production hostname/wildcard, workers.dev or preview URL.
- Access audience with the distinct staging application's audience and a validated HTTPS team issuer. Same team is permitted; same application audience is not.
- Limiter namespace with a distinct numeric namespace.
- `main`, `assets.directory`, and `DB.migrations_dir` with absolute checkout paths to `src/astro-worker.ts`, `public`, and `migrations`. This source config is for **building**, never direct deployment.

Retain server source maps, default-entrypoint cache disabled, `PublicReads` cache enabled and the exact scoped Worker-first list. No D1 `remote: true`, local-write bypass, environment fallback, extra service/resource or background trigger is accepted. The adapter keeps `remoteBindings: false`; sessions/images stay disabled. Do not put secrets or private grants in the config.

```bash
CF_STAGING_CONFIG=/private/approved-staging/wrangler.json npm run build
npm run release:staging:check -- dist-staging/server/wrangler.json
npx wrangler deploy --config dist-staging/server/wrangler.json --dry-run
```

Source isolation is checked before the adapter uses it; `dist-staging/` cannot replace `dist/`. Generated checks validate real entry/client paths and scan public files/imports for source/maps/SQL/config/private markers. Dry run checks packaging/configuration, **not ownership, deployed traffic, Access or policy matches**. Use only an explicitly approved generated deployment config; never rely on implicit Wrangler deploy-config discovery after switching builds.

With specific deployment/security approvals, protect dashboard paths, `/dashboard/api/*`, private previews and alternate/path variants using staging Access. Verify stable JWT identity, issuer/audience/signature/expiry and service identities at the Worker too. Valid login without a private grant stays denied. Keep an independent recovery path; never weaken JWT/zone/crawler policy to make tests pass.

Staging deliberately retains production canonical/discovery URLs; use the smoke CLI's explicit `--canonical` argument. That does not certify production canonical agreement. Staging indexing/perimeter policy needs separate review: the probe expects the existing public-indexability contract and intentionally fails if a staging perimeter/noindex policy differs. Do not remove protection merely to get green output.

## 4. Separate reversible releases

| Boundary                                                                                            | Advance only after                                                                                        | Recovery constraint                                                                                   |
| --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Additive `0006`, then `0007`; reviewed active patches                                               | Current private-copy/old-runtime rehearsal, exact approval, fresh backup/bookmark                         | Keep tables/triggers/receipts/allocators; no down-migration/drop shortcut                             |
| Compatible reader/adapter/assets/discovery and editorial code; **no grants/native publication yet** | Local checks, staging signed journeys/Access denials, independent review                                  | Prior app fallback only before native citations and after actual runtime rehearsal; additive D1 stays |
| Private grants                                                                                      | Explicit identity/capability approval and recovery evidence                                               | Contributors remain excluded from review/publication                                                  |
| Each native publication/collection                                                                  | Compatible readers/clients, allocated IDs, independent exact-version approval, current facts/entitlements | Keep lifecycle/runbook-aware readers and stable citations during rollback                             |
| Public seed refresh                                                                                 | Successful approved remote verification/export                                                            | Current public snapshots only, never a recovery backup                                                |

The ordinary active list is shared from `scripts/verify-content.py`; `local-starters.sql` is **never** a remote patch/seed/publication mechanism. Do not publish disposable IDs. Reverify starter dates/entitlements; use editorial commands to allocate actual IDs, submit, independently review and publish. Verify curated selectors after each complete pair. No legacy conversion is authorized.

The old v0.8 app's **SQL** can remain compatible while its **reader is not**: it lacks native citations/v2. Earlier typed readers may omit lifecycle or reject runbook bodies. After native publication, rollback to such code is unsafe. Retain an artifact with current native/lifecycle/runbook support, or rehearse and separately approve content recovery. Do not delete frozen history, contributors, receipts or reservations to force compatibility. No destructive contract/schema phase is implemented or approved here.

## 5. Live verification, purge and recovery

Only on an explicitly approved deployed target:

```bash
npm run release:smoke -- --base https://approved.example.com --expect-cache-hits
# After an authorized genuine publication, use its ACTUAL ID and revision:
npm run release:smoke -- --base https://approved.example.com \
  --native-id 123 --expected-revision 7 --expect-cache-hits
```

For intentional staging canonicals only add `--canonical https://canonical.example.com`; never conceal a production mismatch. Probes have no default target, credentials, cookies, write methods or redirect following. Responses are timed out and bounded to 2 MiB each; excess fails, never silently truncates. Output is check names/results, not raw responses/Access redirects.

Checks cover HTML/negotiated Markdown/q exclusions/HEAD, explicit Markdown, public OPTIONS, v1 exclusion/native expected-revision parity, sitemap/agent discovery/served skill digest, anonymous dashboard/API/preview denial and optional repeated independent HTML/Markdown HITs. It is not an exhaustive crawl. A perimeter can also deny a request: inspect actual Access configuration and signed behavior separately. An expected-revision check without a publication is not a purge test.

For each approved genuine mutation privately retain the actor/exact command/body/version/key and response/uncertainty. Confirm unchanged replay returns the same result, changed-data reuse conflicts, invalid JWTs/ungranted actors deny, origin/bytes remain enforced, review independence/revocation/base conflicts work, and previews stay private/no-store/noindex without a public cache tag. Do not add throwaway production content to manufacture evidence.

Warm HTML, negotiated/explicit Markdown, JSON summaries/details/facets, family/catalog and discovery/exports **before** publication. Verify the cache-owning purge, actual new revision, effective query keys, HIT/miss progression and relevant locations afterward with fresh network reads. Random queries/`no-cache` are not proof of purge; browser caches are not purged. Direct SQL/registry changes do not invoke application purges: separately review invalidation of all affected `practices`/`taxonomy` representations or version cache boundaries, then verify live.

If publication committed but purge/response failed, preserve the receipt and replay the **same command/key/actor/version** while authorized; it reattempts purge without republishing. Do not rotate keys, assume timeout means rollback or reflexively restore D1. Changed permissions need explicit recovery approval, never an auth bypass. Local RPC/no-op purge evidence is not edge propagation evidence.

For whole-database recovery, first stop/reconcile writes under an approved plan. Assess **all later legitimate writes/external effects** before choosing a restore point. Rehearse private-copy restore/replay; preserve/reconcile receipts, allocator floors, grants/revocations/reviews and public pointers; invalidate/verify caches before reopening. Restoring older roles can re-enable revoked actors; losing newer receipts can duplicate retries. Never use a public seed as a full restore or publish bookmarks/telemetry. Actual Time Travel restore is separately approved.

Complete the runtime/schema/negotiation/security matrix and browser keyboard/mobile/no-JS/light-dark/clipboard/fragment checks on staging, plus required cross-browser/assistive-technology coverage. Performance review requires `web-perf` and Chrome DevTools. Earlier browser evidence is historical; no new live browser/accessibility/performance certification is claimed.

Only after approved remote verification, export privately, use the existing allowlisted `db:seed:refresh` sanitizer, review the public-only diff and rerun checks. No seed refresh occurred here.

## Evidence and next action

The roadmap records exact current checks/counts. Initial Phase 6 verification passed **210/210 workerd tests**, strict types/import/discovery guards, four patches twice, **5 + 5** Python checks, synthetic tooling checks and the built release-probe journey. Subsequent [search/dependency hardening](development-hardening.md) passes **213/213 workerd + 24/24 frontend checks**, the same content/release matrix, clean installs/audits, regenerated types and a refreshed **12/12-check isolated proof**. Normal Astro check/build and separate **synthetic-target staging build**, generated isolation/artifact checks and deploy **dry runs** pass with patched tooling. Neither milestone involved a remote export/probe, remote write, grant, publication, deployment or security change.

**2026-10-31 follow-up:** an approved current full private export, consistent allocator capture and verified production baseline 5 now pass offline and actual isolated local D1 migration/patch rehearsal. **40 local runtime assertions** cover recorded prior v0.8 source, cross-version replay/conflict, failed-write rollback, current editorial/runbook publication and recovered-state replay. All synthetic writes/grants/publications stayed in separate private probe branches. Final local suite: **213 runtime + 36 frontend**, **9 Python + 7 Node** release checks, strict types/**7 boundary + 3 discovery**, content checks, generated types, Astro check/build and deploy dry run pass; root audit has zero findings. See [evidence and limits](scalability-and-production-readiness.md).

**Next:** independently review exact source/artifact/dependencies and reconcile the exact deployed compatible recovery artifact (v0.8 source with current dependencies is not that proof). Approve exact staging resources/Access design before provisioning/deploying, then complete signed/public/browser/cache staging journeys. Keep Phase 2's combined compatibility gate and Phase 6's live checklist open. Refresh recovery inputs/bookmark before any later approved production mutation; no production migration/deployment has occurred.

## Public references

- [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/), [Wrangler environments](https://developers.cloudflare.com/workers/wrangler/environments/), [configuration](https://developers.cloudflare.com/workers/wrangler/configuration/)
- [Astro adapter](https://docs.astro.build/en/guides/integrations-guide/cloudflare/), [build-time environment selection](https://docs.astro.build/en/guides/integrations-guide/cloudflare/#changed-deploy-to-cloudflare-environment)
- [D1 migrations](https://developers.cloudflare.com/d1/reference/migrations/), [import/export](https://developers.cloudflare.com/d1/best-practices/import-export-data/), [Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)
- [Cache configuration](https://developers.cloudflare.com/workers/cache/configuration/), [per-entrypoint purges](https://developers.cloudflare.com/workers/cache/purge/)
