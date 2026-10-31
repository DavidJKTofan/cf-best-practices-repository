# Operational acceptance and recovery checklist

**2026-10-31 — procedure prepared; operational sign-offs remain open.** The [v1.1 evidence](../rollout-2026-10-31-v1.1.md) reconciles the observed release, not a tested recovery artifact or complete Phase 6 acceptance. This checklist authorizes no remote operation. Deployment-approval automation is deferred at the owner's request, not implemented by this work.

## Owners and exit evidence

Roles below identify who must act, not newly appointed people or production grants. The repository owner must name the actual operators/reviewers and privately acknowledge responsibility before the corresponding journey. Missing assignments are blockers; an AI self-review is not independent acceptance.

| Open task                                | Accountable role                                                          | Evidence required to close                                                                                                                               | Exact next action                                                                                                  |
| ---------------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Observed v1.1 scope/limits acceptance    | Repository owner / release owner                                          | Acknowledged exact source/version, exclusions and accepted remaining risks; not inherited from the earlier release                                       | Reconcile the [v1.1 record](../rollout-2026-10-31-v1.1.md) with the owner's approval record                        |
| Independent Phase 2–6 review             | Independent code/security and content reviewers, to be assigned           | Reviewed schema/allocator/publication/auth/export/cache seams, SQL normalization/native isolation, current public sources and dependency disposition     | Assign reviewers and record findings/disposition against the exact diff                                            |
| Exact recovery artifact                  | Recovery operator, to be assigned                                         | Matching retained manifest/artifacts and approved isolated runtime rollback/recovery results                                                             | Capture and reconcile provenance as specified below; do not label a rebuild “exact”                                |
| Staging and Access                       | Environment/Access operator, to be assigned by owner                      | Explicitly approved isolated resources and synthetic/public-data signed/browser/denial journeys                                                          | Submit the concrete private resource/Access design before provisioning                                             |
| Authenticated retries and purge recovery | Authorized application operator plus independent reviewer, to be assigned | Staging journeys first; separately approved genuine production mutation/replay/conflict, private-preview denial and warmed-representation purge evidence | Plan a real operation and recovery path; never add throwaway production content                                    |
| Monitoring acceptance                    | Release observer, to be assigned                                          | Timestamped baseline, completed observation windows and disposition of regressions                                                                       | Agree private thresholds and observation start/end times before claiming a soak                                    |
| Browser/accessibility and scale coverage | Test owner, to be assigned                                                | Named browser/assistive-technology matrix and measured expanded-catalog query/export/load results                                                        | Prioritize the matrix/dataset; existing Chrome/lab observations are not certification                              |
| Native publication and grants            | Repository owner and independent exact-version reviewer                   | Preceding publication/recovery gates, explicit identity/capability approval, current facts/entitlements and allocated IDs                                | Keep pilots/starters disposable until these prerequisites pass; legacy conversion still needs its reviewed adapter |

## Private release/recovery manifest

For each approved release, retain a new restricted private directory and a manifest binding all of the following. Do not place private paths, raw configuration/telemetry, identities, secrets, backups or bookmarks in this public repository.

- Full source commit, source tree cleanliness, lockfile digests, exact Node/package-manager/Wrangler/framework versions and install/build commands.
- Build/deployment/serving-version identifiers and timestamps, generated configuration digest, resolved binding/route/cache/asset settings and independently inspected target. Keep sensitive resolved values private.
- Exact server bundle/module inventory and digests, matching static-asset manifest/digests and server source maps. Record how the bytes were captured from the deployment/build; a newly built `dist/` is only a candidate until matched.
- Previous compatible deployed candidate and its corresponding retained bytes/configuration/dependencies/assets, schema baseline, lifecycle/runbook/client requirements and expected user-visible regression on rollback.
- Private backup/allocator/bookmark provenance and freshness for any approved D1 operation; reconciliation of concurrent/later writes, receipts, grants/revocations and published pointers. A code rollback does not restore D1, and a public seed is never a backup.
- Independent review/owner disposition, operator assignment, approved scope, preflight/live checks, rollback/stop criteria and every unresolved limit.

Keep the current and compatible previous recovery sets at least through the owner-approved rollback/observation window, and longer while citations or retry/data contracts require them. Record retention and access ownership privately; do not routinely delete receipts, frozen revisions or allocator history to simplify recovery.

**Closure requires** matching provenance plus a separately approved isolated runtime rehearsal of public representations, legacy writes/replays/conflicts, native/lifecycle/runbook reads where applicable, private preview denial and recovery reconciliation. Record cache/purge and actual Time Travel limits explicitly. The known previous version in the v1.1 record remains a candidate, not permission to roll back or evidence that this closure passed.

## Observation windows and acceptance criteria

Proposed routine: capture a comparable pre-change baseline, observe the first **30 minutes** after an approved release, then review the next **24 hours** before operational sign-off. The owner may agree different windows explicitly. These windows are a plan, not evidence of a running monitor or a completed v1.1 soak; elapsed wall-clock time and one successful probe do not satisfy them.

The assigned observer records start/end times, traffic/sample sufficiency, expected rejections and findings privately. Agree numerical error/latency/query-cost/cache thresholds against the same routes, traffic class and cache state before the window; do not invent them after seeing results or publish deployment-specific security thresholds. Insufficient traffic/evidence keeps the sign-off open.

| Signal                           | Accept when evidenced                                                                                                                | Stop/escalation condition                                                                                                                                   |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public reads and representations | Baseline plus `--expect-legacy-filters` smoke passes; HTML/Markdown/JSON/discovery, noindex/robots and canonical contracts agree     | A repeatable representation/filter/count/discovery regression or unexpected public failure                                                                  |
| Access and privacy               | Anonymous denials remain; separately authorized signed journeys obey grants; previews remain private/no-store                        | Any draft/private data exposure, authorization bypass or shared-cache personalization: stop the affected workflow and escalate immediately                  |
| Worker errors and latency        | Issues/logs/traces show no unexplained new exceptions/5xx, with latency within the agreed comparable baseline                        | New release-correlated exceptions/5xx or a sustained threshold breach; exclude documented expected 4xx from application-error claims                        |
| D1 work and cost                 | Query duration, rows read/written and request cost stay within agreed bounds for summaries/counts/facets/deep pages/exports          | Increased query work/latency/cost beyond the agreed baseline; pagination alone is not query-cost proof                                                      |
| Cache correctness                | Repeated independent HTML/Markdown HITs and correct query/Accept separation; genuine approved writes get separate purge verification | Cross-variant/query contamination or stale post-mutation visibility beyond the agreed contract; HITs alone do not prove purge propagation                   |
| Recovery integrity               | Exact candidate and private-state reconciliation are available and tested for the approved scope                                     | Missing compatible artifact, uncertain commit/receipt state or unsafe restore point: stop release advancement, preserve evidence and seek recovery approval |

On failure, record the last-good version and scope, preserve diagnostics/receipts and notify the owner. Stop further rollout/publication as appropriate; execute a code rollback, Access change, write pause or D1 restore **only under its separately approved recovery plan**. Do not weaken bot/Access/cache controls to make smoke green. Rerun relevant reads and authorized journeys after any approved remediation, then restart or explicitly extend the observation window.

## Current completion boundary

- [x] Source/build/deployment/version mapping and targeted read evidence reconciled for v1.1.
- [x] Feature-specific smoke implemented locally, exercised against synthetic/built responses and the existing live target.
- [x] Recovery manifest requirements, role ownership, monitoring windows and acceptance/stop criteria documented.
- [ ] Actual operator/reviewer assignments and owner acceptance reconciled privately.
- [ ] Exact deployed recovery bytes retained/matched and runtime recovery independently accepted.
- [ ] Monitoring thresholds/baseline/windows completed and signed off.
- [ ] Staging, authenticated/purge journeys and broader certification/publication gates closed with evidence.

**Next:** owner reviews the local documentation/probe diff, assigns the release observer/recovery operator/independent reviewers and reconciles the recorded v1.1 acceptance. Then plan the specifically approved private provenance/recovery and staging journeys. No commit, push, redeployment or remote write follows automatically from this checklist.
