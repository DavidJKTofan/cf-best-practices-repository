import { env } from 'cloudflare:workers';
import { beforeAll, expect, it } from 'vitest';
import starters from '../data/phase5/starters.json';
import { PublicReads } from '../src/index';
import { validateContent } from '../src/content/validation';
import { readingSections } from '../src/content/presentation';
import { entryMarkdown } from '../src/content/markdown';
import { starterCollection } from '../src/modules/catalog/starter-collections';

const reads = () => new PublicReads({}, env);
const call = (path) => reads().fetch(new Request(`https://catalog.example.com${path}`));
const unescape = (value) => value.replace(/\\([\\`*_{}\[\]<>()#+.!|~-])/g, '$1');
beforeAll(async () => {
	await env.DB.batch(env.TEST_CATALOG_SQL.map((sql) => env.DB.prepare(sql)));
	await env.DB.batch(env.TEST_STARTER_SQL.map((sql) => env.DB.prepare(sql)));
});

it.each(starters)('validates and round-trips authored starter $id through the published detail boundary', async ({ id, content }) => {
	expect(validateContent(content)).toEqual(content);
	const response = await call(`/api/v2/entries/${id}`);
	expect(response.status).toBe(200);
	const { data } = await response.json();
	expect(data).toMatchObject({ ...content, practiceId: id, v1Eligible: false });
	const markdown = unescape(entryMarkdown(data));
	for (const section of readingSections(validateContent(content))) {
		expect(markdown).toContain(`## ${section.title}`);
		for (const text of [...(section.items ?? []), ...(section.paragraphs ?? [])]) expect(markdown).toContain(text);
	}
	if (content.body.variant) expect(markdown).toContain('## Read-only diagnosis');
});

it('rejects incomplete, mixed, unknown or unbounded runbook variants instead of accepting guide-shaped fallbacks', () => {
	for (const change of [
		(c) => {
			delete c.body.recovery;
		},
		(c) => {
			c.body.diagnostics = [];
		},
		(c) => {
			c.body.safeChanges = Array(21).fill('Too many');
		},
		(c) => {
			c.body.variant = 'unknown';
		},
		(c) => {
			c.body.steps = ['Mixed schema'];
		},
		(c) => {
			delete c.body.variant;
		},
		(c) => {
			c.body.task = 'x'.repeat(5001);
		},
	]) {
		const candidate = structuredClone(starters[1].content);
		change(candidate);
		expect(() => validateContent(candidate)).toThrow();
	}
});

it('populates two starter journeys and conjunctive read facets without adding native entries to v1', async () => {
	for (const family of ['cloudflare-one', 'developer-platform']) {
		const { data, total } = await (await call(`/api/v2/entries?family=${family}&type=implementation-guide`)).json();
		expect(total).toBe(2);
		expect(data).toHaveLength(2);
		expect(data.every((row) => row.families.includes(family))).toBe(true);
	}
	const { data } = await (await call('/api/v2/facets')).json();
	expect(data.families.map(({ slug, count }) => [slug, count])).toEqual([
		['cloudflare-one', 2],
		['developer-platform', 2],
	]);
	const legacy = await (await call('/api/practices')).json();
	expect(legacy.count).toBe(119);
	for (const { id } of starters) expect(legacy.data.some((row) => row.practice_id === id)).toBe(false);
});

it('re-applies the complete local snapshot without mutating public revisions or ID sequences', async () => {
	const before = await env.DB.prepare('SELECT * FROM sqlite_sequence ORDER BY name').all();
	const revisions = await env.DB.prepare('SELECT * FROM CatalogRevisions ORDER BY revision_id').all();
	await env.DB.batch(env.TEST_STARTER_SQL.map((sql) => env.DB.prepare(sql)));
	expect((await env.DB.prepare('SELECT * FROM sqlite_sequence ORDER BY name').all()).results).toEqual(before.results);
	expect((await env.DB.prepare('SELECT * FROM CatalogRevisions ORDER BY revision_id').all()).results).toEqual(revisions.results);
});

it('orders published starter summaries deliberately and rejects unknown/inherited collection names', async () => {
	const session = env.DB.withSession('first-primary');
	const collection = await starterCollection(session, 'cloudflare-one');
	expect(collection.entries.map((row) => row.practiceId)).toEqual([810001, 810002]);
	expect(collection.entries.every((row) => !Object.hasOwn(row, 'body'))).toBe(true);
	for (const family of ['network-services', 'constructor', 'toString', '__proto__'])
		expect(await starterCollection(session, family)).toBeNull();
});

it.each(['unpublished', 'ambiguous', 'retired'])('hides a curated pair when a required member is %s', async (state) => {
	const revision = state === 'retired' ? 900002 : 900001;
	try {
		if (state === 'unpublished') {
			await env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = NULL WHERE practice_id = 810002').run();
		} else {
			const id = state === 'ambiguous' ? 900001 : 810002;
			if (state === 'ambiguous') await env.DB.prepare('INSERT INTO CatalogEntries (practice_id) VALUES (?)').bind(id).run();
			await env.DB.prepare(
				`INSERT INTO CatalogRevisions
			(revision_id, practice_id, schema_version, content_type, title, summary, primary_family, applicability_json,
			body_json, evidence, maturity, modified_at, fact_verified_at, review_due_at, lifecycle_json)
			SELECT ?, ?, schema_version, content_type, title, summary, primary_family, applicability_json,
			body_json, evidence, maturity, modified_at, fact_verified_at, review_due_at, ? FROM CatalogRevisions WHERE revision_id = 810002`,
			)
				.bind(
					revision,
					id,
					JSON.stringify(
						state === 'retired'
							? { state: 'deprecated', reason: 'Test retirement', supersededBy: null }
							: { state: 'active', reason: null, supersededBy: null },
					),
				)
				.run();
			await env.DB.batch([
				env.DB.prepare('INSERT INTO CatalogRevisionTaxa SELECT ?, kind, slug FROM CatalogRevisionTaxa WHERE revision_id = 810002').bind(
					revision,
				),
				env.DB.prepare(
					'INSERT INTO CatalogRevisionSources SELECT ?, position, url, title FROM CatalogRevisionSources WHERE revision_id = 810002',
				).bind(revision),
				env.DB.prepare("INSERT INTO CatalogPublications VALUES (?, ?, '2026-10-30')").bind(id, revision),
				env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = ?').bind(revision, id),
			]);
		}
		expect(await starterCollection(env.DB.withSession('first-primary'), 'cloudflare-one')).toBeNull();
	} finally {
		await env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = 810002 WHERE practice_id = 810002').run();
		if (state === 'ambiguous')
			await env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = NULL WHERE practice_id = 900001').run();
	}
});
