# Phase 0: low-fidelity field-guide wireframes

**Proposed, awaiting owner review.** These specify content hierarchy, not finished branding or implemented routes. The isolated Astro screen is only a compatibility specimen. Design intent: an engineer's field notebook—quiet paper/ink, crisp section rules, restrained product-family accents, readable serif headings and monospace labels. Avoid a metrics dashboard or card grid pretending to be documentation.

## 1. Homepage — choose a journey

```text
CF / FIELD GUIDE                           Browse all | About | Theme
----------------------------------------------------------------------
Recommendations and patterns for the Cloudflare platform
Unofficial, sourced guidance. Validate applicability before deployment.

Find a pattern  [ query................................ ] [ Search ]

EXPLORE BY PRODUCT                 START WITH AN OUTCOME
Application services              Protect an application
Cloudflare One                    Connect private applications
Developer Platform                Build a reliable service
[Other populated families]        Operate the platform

START HERE
[type] Title / one-line purpose / products / applicability caveat
[type] Title / one-line purpose / products / evidence status

Browse all guidance ->          Sources / Markdown / API / Disclaimer
```

No fake counts or “recently verified” label derived from `updated_at`. Only show populated families. Form performs GET navigation without JavaScript.

## 2. Family/product hub — orient before listing

```text
Home / Cloudflare One
----------------------------------------------------------------------
Cloudflare One
Identity, connectivity, and policy: where each fits in the traffic flow.

STARTING POINTS               CAPABILITIES
Connect a web application    Access | Tunnel | Gateway | Client
Connect private networks     [cross-family products link to one entry]

Recommended reading path
1 Architecture -> 2 Policy design -> 3 Implementation -> 4 Operations

[Search within family.............] [Type v] [Outcome v] [Apply]
[filtered result rows]                           View all family entries
```

Do not imply Tunnel alone provides identity authorization. Curated journeys can cross families without duplicating records.

## 3. Results — shared summary, useful type previews

```text
Browse / search: "private application"
----------------------------------------------------------------------
[query.....................] [ Search ]          Sort [Relevance v]
Filters                        Active: Cloudflare One [remove] | Clear
 Family [....]                 N matching entries [real facet count]
 Product [....]
 Type [....]                   ARCHITECTURE  Access + Tunnel
 Outcome [....]                Browser access to a self-hosted app ->
 [Apply]                       Scenario / trust boundary / prerequisites

                               POLICY EXAMPLE  Access
                               Narrow application access ->
                               Context / decision / rollout caveat

                               Previous   1 2 3   Next
```

Summary projection only; no hidden full-body catalog download. Query/filter/sort/page URLs preserve effective server state. Stable ordering includes an ID tie-breaker. Empty state explains how to broaden filters; errors preserve the query and offer retry.

## 4. Rule/policy reading — expression is not the action

```text
Home / Application services / WAF              Markdown | Copy link
----------------------------------------------------------------------
POLICY EXAMPLE        Title                     CONTENTS
Purpose / applicability                         Prerequisites
Products / scope / phase / availability          Conditions
                                                Action
Prerequisites and exclusions                     Rollout
Example conditions [language/context]            Verification
+---------------------------------------------------------------+
| expression / policy conditions                   [Copy] [Wrap] |
+---------------------------------------------------------------+
Action/configuration — separate from match conditions
Observe -> enforce -> rollback; API/browser caveats
Sources | fact verified (or unknown) | editorial update | related
```

Start with preserved practice 18. Code stays readable without copy buttons. Never label a syntax-only dry run as validation of real traffic matches.

## 5. Architecture reading — explain flow and trust

```text
Home / Cloudflare One                          Markdown | Copy link
----------------------------------------------------------------------
REFERENCE ARCHITECTURE     Title / intended scenario
Assumptions | applicable products | exclusions | entitlement caveats

 [Browser] -> [Access / identity policy] -> [Tunnel] -> [Origin]
                    <-> [Identity provider]
 Diagram caption and numbered text description (also in Markdown)

1 Traffic path and trust boundaries
2 DNS / routing / identity prerequisites
3 Deployment choices and trade-offs
4 Failure modes, availability, observation and verification
5 Recovery / rollback
Sources / evidence / related policy and implementation guidance
```

Diagram is reviewed static content with a text equivalent, not arbitrary stored SVG/HTML. Keep public-hostname and private-network scenarios distinct. Do not imply topology alone grants authorization.

## 6. Developer-pattern reading — files, failures, verification

```text
Home / Developer Platform / Workers             Markdown | Copy link
----------------------------------------------------------------------
IMPLEMENTATION GUIDE     Durable creation with D1
Problem: response lost after commit
Applies when... | Does not solve... | Cost/retention trade-offs

Runtime / bindings / prerequisites
Files
  validation.ts    command.ts    repository.ts    schema.sql
  [filename + language + purpose + content]          [Copy]

Request -> validate -> actor/key receipt -> D1 transaction -> purge
Failure behavior: retry / conflict / permanent failure / purge failure
Tests: lost response, concurrent retry, rollback, malformed/large body
Observe: errors without keys/tokens; no false exactly-once claim
Safe rollout / rollback / receipt retention
Sources / versions / evidence dates / related architectures
```

## Responsive and accessibility requirements

- Mobile: single column; GET-based filter form in a native disclosure above results, active filters always visible, contents collapses into document flow. Code scroll is confined to code, never the whole viewport.
- Every control has a visible label; keyboard focus, skip link, semantic headings/landmarks and status feedback are required. Links describe their destinations.
- System light/dark preference plus later explicit theme control; sufficient contrast, no color-only type/status indicators. No animation needed for essential comprehension.
- Initial HTML includes guidance/links; Markdown includes the same revision and diagram text. No JavaScript dependency for search/filter navigation or reading.
- Private editorial views are separate, protected, no-store/noindex. Public reading never includes a preview/draft toggle.

## Owner review requested

Confirm family labels, “field guide” reading direction, outcome entry points, independent type labels, and whether the three pilots represent the intended breadth. Approval is deliberately separate from passing compatibility tests.
