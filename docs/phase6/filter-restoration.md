# Recorded practice filters and scannable labels

**2026-10-31 — committed as `53e1f32` and deployed by the existing `main` push integration.** Read-only inspection confirms version `c24694a9-f6e1-42e6-8358-55f1fb7e5cb5` serves 100% traffic. See the [v1.1 deployment/read evidence](../rollout-2026-10-31-v1.1.md), which supersedes this document's original local-only status without extending the [initial scoped release approval](../rollout-2026-10-31.md). No deployment, remote database write, role, publication or security change was performed by this verification.

## Usability and compatibility

- The classifications were never lost from D1: the Astro catalog omitted their controls. Restore **Category, Feature, Domain, Level, Impact and Difficulty** as visible native GET selects when populated or selected.
- Reuse the earlier Domain palette: Security/red, Performance/blue, Reliability/green, General/gray. Every pill includes its text; a labeled legend accompanies matching legacy listings. Category/Feature pills stay neutral so Domain remains the consistent color cue. Results show recorded Level/Impact/Difficulty as labeled text; reading headings reuse classification pills.
- Individually removable active-filter links preserve the other effective filters and sort/page size, resetting pagination. Selected zero-result controls retain their readable labels and remain clearable. Empty native taxonomy controls, practice groups and legends are omitted server-side.
- Keep the owner's compact system-font layout and both themes. Mobile uses full-width Category/Feature controls and paired shorter controls. No new client dependency, remote font or full-body result download.
- Existing enhancement handles the same SSR form: 350 ms text debounce, immediate selects, cancellation/IME/timeout protection, focus/caret/disclosure and metadata/history preservation. Native Search, clear/removal links, pagination and reading remain usable without JavaScript.

## Additive read contract

`/catalog`, `/families/{slug}` and their Markdown forms, `/api/v2/entries` and `/api/v2/facets` share normalization of all six filters. IDs are digit-only positive values up to 2147483647, with leading zeros normalized away. Enums retain existing case-sensitive values. First duplicate wins; malformed values disappear from SQL/cache/document state; unknown valid IDs match no entries. Every filter combines with AND, and facet counts remain conjunctive, not self-excluding. Pagination remains 20/default and 50/maximum summaries; it does not bound substring/count/deep-offset costs.

Summary/detail `legacyClassification` contains `domain`, `categoryId`, `category`, `featureId`, `feature`, `level`, `impact`, `difficulty`. Unrecorded fields are null; native entries have null for the whole property. Facets add `data.legacy.{categories,features,domains,levels,impacts,difficulties}` arrays of `{value,label,count}`; IDs are string values. Only matching published legacy records contribute. Native family/product/outcome taxonomy remains separate: combining a practice filter with native taxonomy returns no entries. Unchanged v1 uses `area`, not `domain`, and gains no new fields or Difficulty filter.

`legacy-discovery.ts` centralizes the summary-only projection and joins. The legacy join requires `schema_version = 0` and `revision_id IS NULL` on `PublishedCatalog`; taxonomy and private drafts do not provide legacy labels. Facets expand six scalar pairs through SQLite-generated JSON in one aggregation, avoiding repeated compound-view expansion beyond workerd's compound SELECT limit. No schema, migration, seed, receipt, authorization or cache-policy change. Reads still start first-primary and share the `practices` purge tag. Native preview projections explicitly retain null classification.

OpenAPI, API docs, the generated agent index, read skill/digest and optional read-only WebMCP describe the additive filters. Markdown listings include recorded labels alongside the same bounded summaries.

## Original local verification and limits

- Runtime **225/225**, rebuilt frontend **37/37**, strict TypeScript, **7 boundary + 3 discovery**, content integrity/four ordinary patches twice/**5 + 5 Python**, synthetic release **9 Python + 9 Node**, generated binding types, clean Astro check/build, generated-config deploy dry run and `git diff --check` pass. Skill digest matches the served Markdown bytes. The existing Node test-runner module-type warning is unchanged; no dependency/configuration changes were needed.
- Chrome checked **40 script-enabled combinations**: unfiltered and filtered catalog, legacy reading and typed code reading; **20 script-blocked combinations**: catalog and typed code reading. Actual CSS viewports 320, 390, 768, 1440 and 3840px, both themes. No horizontal overflow; 4K listing/reading widths remain 1440/1120px.
- Computed contrast of rendered classification pills, rating labels, legend labels and entry metadata is at least **5.76:1 light / 8.06:1 dark** in the checked pages, including alpha-composited backgrounds. This is targeted evidence, not a full accessibility certification.
- Live six-filter combination: focus stays on each changed select, disclosure remains open, readable removable chips and canonical/Markdown URLs update. Zero-result text search retains caret/selection and all six selected controls; Back restores the previous effective query. Keyboard Tab shows a 2px focus outline; Enter removes only the targeted filter.
- Script-blocked browser: submitted all six filters through the native form; separate Domain/per-page filtering and next-page navigation preserved state. Removing the Domain chip on page 2 resets to page 1 and preserves page size. Native code remains readable with no unusable visible copy buttons.
- Fresh final-build preview: practice 18 retains its Domain/Category/Feature labels and complete reading sections; its existing copy control reports **“Expression copied.”** No code/copy implementation changed.
- One cold, unthrottled local catalog trace: **LCP 66 ms, TTFB 11 ms, CLS 0.00**; normal script/style/document requests returned 200 with no warning/error console messages. Render-blocking savings were 0 ms. Not a production, field, expanded-catalog or load benchmark.

## Subsequent production verification

The [v1.1 review](../rollout-2026-10-31-v1.1.md) confirms the six live controls, public classification/facet/count/Markdown parity, normalization/selected-empty links and independent cache variants. The local smoke CLI now supports `--expect-legacy-filters`; all **10 groups** pass against the existing production version when HIT checks are requested. Its synthetic and actual built-Worker regressions are separate from live evidence. No D1 migration, data patch or new Worker deployment is needed to run the probe.

The owner subsequently requested commit and production deployment of the documentation/probe follow-up: `2e9c50c` deployed through Workers Builds, exact-commit CI and **10/10 post-deploy smoke groups** passed. See [release evidence](../rollout-2026-10-31-v1.1.md). No application/schema/data/binding changes were included.

Independent review, cross-browser/screen-reader certification and the existing staging, exact-artifact recovery, authenticated production mutation/retry and purge-propagation limits remain open. Follow the [operational acceptance checklist](operational-acceptance.md) for ownership, recovery provenance and monitoring sign-off. Obtain explicit approval before later remote operations; this scoped request did not close those gates.
