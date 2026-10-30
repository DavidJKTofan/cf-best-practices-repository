import { env } from 'cloudflare:workers';
import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import worker, { PublicReads } from '../src/index';
import { validateContent } from '../src/content/validation';
import { CONTENT_TYPES } from '../src/content/types';
import { normalizeV2Request } from '../src/modules/catalog/v2-filters';
import { contentFixture } from './fixtures/catalog-content';
import { createPractice } from '../src/modules/catalog/creation';
import { validatePractice } from '../src/practice-validation';

const ORIGIN = 'https://catalog.example.com';
async function call(path, init = {}, overrides = {}) {
	const ctx = createExecutionContext();
	const response = await worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...overrides }, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}
async function storeRevision(id, input, publish = false) {
	const c = validateContent(input);
	await env.DB.prepare('INSERT OR IGNORE INTO CatalogEntries (practice_id) VALUES (?)').bind(id).run();
	const { revision_id: revisionId } = await env.DB.prepare(
		`INSERT INTO CatalogRevisions
		(practice_id, schema_version, content_type, title, summary, primary_family, applicability_json, body_json, evidence, maturity, modified_at, fact_verified_at, review_due_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING revision_id`,
	)
		.bind(
			id,
			c.schemaVersion,
			c.type,
			c.title,
			c.summary,
			c.primaryFamily,
			JSON.stringify(c.applicability),
			JSON.stringify(c.body),
			c.evidence,
			c.maturity,
			c.modifiedAt,
			c.factVerifiedAt,
			c.reviewDueAt,
		)
		.first();
	const statements = [];
	for (const [kind, slugs] of [
		['family', c.families],
		['product', c.products],
		['outcome', c.outcomes],
	]) {
		for (const slug of slugs)
			statements.push(
				env.DB.prepare('INSERT INTO CatalogRevisionTaxa (revision_id, kind, slug) VALUES (?, ?, ?)').bind(revisionId, kind, slug),
			);
	}
	c.sources.forEach((source, position) =>
		statements.push(
			env.DB.prepare('INSERT INTO CatalogRevisionSources (revision_id, position, url, title) VALUES (?, ?, ?, ?)').bind(
				revisionId,
				position,
				source.url,
				source.title,
			),
		),
	);
	if (publish) {
		statements.push(
			env.DB.prepare('INSERT INTO CatalogPublications (practice_id, revision_id, published_at) VALUES (?, ?, ?)').bind(
				id,
				revisionId,
				'2026-10-30',
			),
		);
		statements.push(env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = ?').bind(revisionId, id));
	}
	await env.DB.batch(statements);
	return revisionId;
}
beforeAll(async () => {
	await env.DB.batch([
		env.DB.prepare(`INSERT INTO CatalogTaxa (kind, slug, label) VALUES
			('family', 'application-services', 'Application services'), ('family', 'cloudflare-one', 'Cloudflare One'), ('family', 'developer-platform', 'Developer Platform'),
			('product', 'waf', 'WAF'), ('product', 'access', 'Access'), ('product', 'tunnel', 'Tunnel'), ('product', 'workers', 'Workers'), ('product', 'd1', 'D1'),
			('product', 'draft-only', 'DRAFT_ONLY_TAXONOMY')`),
		env.DB.prepare(
			`INSERT INTO BestPractices (practice_id, title, description, domain, source_reference)
			VALUES (1, 'Legacy %_ literal', 'Legacy full body.', 'Security', 'https://developers.cloudflare.com/'),
			(2, ?, 'Long Unicode title fixture.', 'General', 'https://developers.cloudflare.com/')`,
		).bind('界'.repeat(100)),
	]);
	for (const [index, type] of CONTENT_TYPES.entries()) await storeRevision(100 + index, contentFixture(type), true);
	await storeRevision(100, { ...contentFixture(), title: 'UNPUBLISHED_REVISION', products: ['draft-only'] });
	await storeRevision(200, { ...contentFixture(), title: 'UNPUBLISHED_ENTRY', products: ['draft-only'] });
	await env.DB.prepare('INSERT INTO CatalogDrafts (practice_id, content_json) VALUES (?, ?)')
		.bind(100, JSON.stringify({ title: 'PRIVATE_WORKING_DRAFT' }))
		.run();
});
afterEach(() => vi.restoreAllMocks());

describe('bounded typed content validation', () => {
	it.each(CONTENT_TYPES)('round-trips representative %s bodies without coercion', (type) => {
		const input = contentFixture(type);
		expect(validateContent(JSON.parse(JSON.stringify(input)))).toEqual(input);
	});
	it.each([
		[
			'unknown schema',
			(c) => {
				c.schemaVersion = 99;
			},
		],
		[
			'unknown type',
			(c) => {
				c.type = 'operational-runbook';
			},
		],
		[
			'unknown metadata',
			(c) => {
				c.privateReviewer = 'fixture';
			},
		],
		[
			'missing applicability',
			(c) => {
				delete c.applicability;
			},
		],
		[
			'primary family mismatch',
			(c) => {
				c.primaryFamily = 'cloudflare-one';
			},
		],
		[
			'duplicate association',
			(c) => {
				c.products.push(c.products[0]);
			},
		],
		[
			'unsafe URL',
			(c) => {
				c.sources[0].url = 'javascript:alert(1)';
			},
		],
		[
			'credential URL',
			(c) => {
				c.sources[0].url = 'https://user:pass@example.com/';
			},
		],
		[
			'false verification date',
			(c) => {
				c.factVerifiedAt = '2026-10-30';
			},
		],
		[
			'invalid calendar date',
			(c) => {
				c.modifiedAt = '2026-02-30';
			},
		],
		[
			'too many blocks',
			(c) => {
				c.body.guidance = Array(31).fill({ kind: 'prose', text: 'fixture' });
			},
		],
		[
			'executable blocks',
			(c) => {
				c.body.guidance = [{ kind: 'html', text: '<script>fixture</script>' }];
			},
		],
		[
			'nested prose',
			(c) => {
				c.body.guidance[0].text = { text: 'fixture' };
			},
		],
		[
			'NUL',
			(c) => {
				c.title = 'bad\0title';
			},
		],
		[
			'unpaired surrogate',
			(c) => {
				c.title = '\ud800';
			},
		],
	])('rejects %s', (_, mutate) => {
		const input = contentFixture();
		mutate(input);
		expect(() => validateContent(input)).toThrow('Invalid catalog content');
	});
	it('bounds total UTF-8 bytes independently of per-string limits', () => {
		const input = contentFixture();
		input.body.guidance = Array(10).fill({ kind: 'prose', text: '界'.repeat(3000) });
		expect(() => validateContent(input)).toThrow('64 KiB');
	});
	it('requires type-specific sections and product consistency', () => {
		for (const type of CONTENT_TYPES) {
			const input = contentFixture(type);
			delete input.body.validation;
			expect(() => validateContent(input)).toThrow();
		}
		const rule = contentFixture('rule-policy');
		rule.body.product = 'workers';
		expect(() => validateContent(rule)).toThrow('product');
	});
});

describe('v2 canonical state and gateway policy', () => {
	it('normalizes only effective state, idempotently, with deterministic duplicate/default handling', () => {
		const request = new Request(
			`${ORIGIN}/api/v2/entries?unused=x&page=0002&page=9&pageSize=999&sort=bad&type=rule-policy&q=%20hello%00world%20&family=cloudflare-one&product=bad%20slug`,
		);
		const normalized = normalizeV2Request(request);
		expect(normalized.url).toBe(`${ORIGIN}/api/v2/entries?q=hello+world&family=cloudflare-one&type=rule-policy&page=2&pageSize=50`);
		expect(normalized.headers.get('Accept')).toBe('application/json');
		expect(normalizeV2Request(normalized).url).toBe(normalized.url);
		const boundary = normalizeV2Request(new Request(`${ORIGIN}/api/v2/entries?q=${encodeURIComponent('x'.repeat(199) + ' y')}`));
		expect(normalizeV2Request(boundary).url).toBe(boundary.url);
		expect(normalizeV2Request(new Request(`${ORIGIN}/api/v2/facets?page=2&sort=newest&pageSize=5&q=test`)).url).toBe(
			`${ORIGIN}/api/v2/facets?q=test`,
		);
		expect(normalizeV2Request(new Request(`${ORIGIN}/api/v2/entries/1?preview=true`)).url).toBe(`${ORIGIN}/api/v2/entries/1`);
	});
	it('rate-limits before forwarding canonical requests to the owning cached entrypoint', async () => {
		const fetch = vi.fn().mockResolvedValue(Response.json({ success: true }));
		const limit = vi.fn().mockResolvedValue({ success: true });
		await worker.fetch(
			new Request(`${ORIGIN}/api/v2/entries?page=01&sort=title&q=fixture&tracking=x`),
			{ ...env, MY_RATE_LIMITER: { limit } },
			{ exports: { PublicReads: { fetch } } },
		);
		expect(fetch.mock.calls[0][0].url).toBe(`${ORIGIN}/api/v2/entries?q=fixture`);
		expect(limit.mock.invocationCallOrder[0]).toBeLessThan(fetch.mock.invocationCallOrder[0]);
	});
	it('uses first-primary, existing cache tags/TTLs, public CORS, and API noindex', async () => {
		const withSession = vi.fn().mockImplementation((constraint) => env.DB.withSession(constraint));
		const reads = new PublicReads({}, { ...env, DB: { withSession } });
		const response = await reads.fetch(new Request(`${ORIGIN}/api/v2/entries`));
		expect(withSession).toHaveBeenCalledWith('first-primary');
		expect(response.status).toBe(200);
		expect(response.headers.get('Cache-Tag')).toBe('practices');
		expect(response.headers.get('Cache-Control')).toContain('max-age=60');
		expect(response.headers.get('Cloudflare-CDN-Cache-Control')).toContain('max-age=3600');
		expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
		expect(response.headers.get('X-Robots-Tag')).toBe('noindex');
	});
	it.each(['/api/v2/entries', '/api/v2/facets', '/api/v2/entries/100'])('keeps GET/HEAD/OPTIONS/405 behavior: %s', async (path) => {
		const get = await call(path);
		expect(get.status).toBe(200);
		const head = await call(path, { method: 'HEAD' });
		expect(head.status).toBe(200);
		expect(await head.text()).toBe('');
		expect(head.headers.get('Cache-Tag')).toBe(get.headers.get('Cache-Tag'));
		expect((await call(path, { method: 'OPTIONS' })).status).toBe(204);
		const post = await call(path, { method: 'POST', body: '{}' });
		expect(post.status).toBe(405);
		expect(post.headers.get('Cache-Control')).toBe('no-store');
	});
	it.each([
		'/api/v2/entries/0',
		'/api/v2/entries/0100',
		'/api/v2/entries/2147483648',
		'/api/v2/entries/100/',
		'/api/v2/entries/999',
		'/api/v2/drafts',
	])('rejects invalid/missing routes without caching: %s', async (path) => {
		const response = await call(path);
		expect(response.status).toBe(404);
		expect(response.headers.get('Cache-Control')).toBe('no-store');
	});
});

describe('published-only v2 reads and compatibility', () => {
	it('returns paginated summaries without downloading any bodies', async () => {
		const page = await (await call('/api/v2/entries?pageSize=2')).json();
		expect(page).toMatchObject({ success: true, count: 2, total: 6, page: 1, pageSize: 2, pages: 3 });
		expect(page.data.every((entry) => !('body' in entry) && !('sources' in entry))).toBe(true);
		expect(page.links.next).toBe('/api/v2/entries?page=2&pageSize=2');
		const allIds = new Set();
		let path = '/api/v2/entries?pageSize=2';
		while (path) {
			const body = await (await call(path)).json();
			for (const row of body.data) allIds.add(row.practiceId);
			path = body.links.next;
		}
		expect([...allIds].sort((a, b) => a - b)).toEqual([1, 2, 100, 101, 102, 103]);
		const beyond = await (await call('/api/v2/entries?page=10000')).json();
		expect(beyond.data).toEqual([]);
		expect(beyond.total).toBe(6);
	});
	it.each(CONTENT_TYPES)('round-trips published %s content, sources, and associations', async (type) => {
		const id = 100 + CONTENT_TYPES.indexOf(type);
		const data = (await (await call(`/api/v2/entries/${id}`)).json()).data;
		expect(data).toMatchObject({ ...contentFixture(type), practiceId: id, v1Eligible: false, canonicalPath: `/practices/${id}` });
		expect(data.revisionId).toBeGreaterThan(0);
	});
	it('preserves legacy IDs, complete v1 projection, and unknown evidence without reclassification', async () => {
		const legacy = (await (await call('/api/practices')).json()).data.find((p) => p.practice_id === 1);
		const data = (await (await call('/api/v2/entries/1')).json()).data;
		expect(data).toMatchObject({
			practiceId: 1,
			revisionId: null,
			schemaVersion: 0,
			type: 'legacy-practice',
			primaryFamily: null,
			families: [],
			evidence: 'unreviewed',
			factVerifiedAt: null,
			maturity: 'unknown',
			canonicalPath: '/practices/1',
			body: legacy,
		});
	});
	it('combines filters with AND and reports populated conjunctive facets only', async () => {
		const body = await (await call('/api/v2/entries?family=cloudflare-one&product=tunnel&type=reference-architecture')).json();
		expect(body.data.map((p) => p.practiceId)).toEqual([102]);
		const facets = await (await call('/api/v2/facets?family=cloudflare-one')).json();
		expect(facets.data.types).toEqual([{ slug: 'reference-architecture', count: 1 }]);
		expect(facets.data.products.map((p) => p.slug)).toEqual(['access', 'tunnel']);
		expect((await (await call('/api/v2/entries?family=unknown-family')).json()).total).toBe(0);
	});
	it('treats wildcard/injection/multibyte/long searches as literal bounded text, not SQL patterns', async () => {
		for (const [q, count] of [
			['%_', 1],
			['界'.repeat(100), 1],
			['x'.repeat(200), 0],
			["' OR 1=1 --", 0],
			['\\', 0],
		]) {
			const response = await call(`/api/v2/entries?q=${encodeURIComponent(q)}`);
			expect(response.status).toBe(200);
			expect((await response.json()).total).toBe(count);
		}
	});
	it('uses ID tie-breakers for both allowlisted sorts', async () => {
		await storeRevision(300, { ...contentFixture(), title: 'Same title', modifiedAt: '2026-10-30' }, true);
		await storeRevision(301, { ...contentFixture(), title: 'Same title', modifiedAt: '2026-10-30' }, true);
		for (const sort of ['title', 'newest']) {
			const body = await (await call(`/api/v2/entries?q=Same+title&sort=${sort}&pageSize=1&page=2`)).json();
			expect(body.data.map((p) => p.practiceId)).toEqual([301]);
		}
	});
	it('verifies local FTS5 support while keeping the v2 contract literal rather than token/relevance based', async () => {
		await env.DB.prepare('CREATE VIRTUAL TABLE Phase2FtsProbe USING fts5(content)').run();
		await env.DB.prepare("INSERT INTO Phase2FtsProbe (content) VALUES ('fixture')").run();
		expect(
			(await env.DB.prepare('SELECT content FROM Phase2FtsProbe WHERE Phase2FtsProbe MATCH ?').bind('fixture').all()).results,
		).toHaveLength(1);
		expect(
			(await env.DB.prepare('SELECT content FROM Phase2FtsProbe WHERE Phase2FtsProbe MATCH ?').bind('fixt').all()).results,
		).toHaveLength(0);
		const literal = await (await call('/api/v2/entries?q=fixt')).json();
		expect(literal.data.map((row) => row.practiceId)).toEqual(expect.arrayContaining([100, 101, 102, 103]));
		expect(literal.data.some((row) => row.practiceId === 200)).toBe(false);
	});
	it('never exposes unpublished revisions, entries, drafts, or taxonomy through public read paths', async () => {
		for (const path of [
			'/api/v2/entries',
			'/api/v2/entries/100',
			'/api/v2/facets',
			'/api/practices',
			'/',
			'/index.md',
			'/llms.txt',
			'/llms-full.txt',
			'/sitemap.xml',
			'/practices/1',
			'/practices/1.md',
		]) {
			const response = await call(`${path}?preview=true&draft=true`);
			expect(response.status).toBe(200);
			expect(await response.text()).not.toMatch(
				/UNPUBLISHED_REVISION|UNPUBLISHED_ENTRY|PRIVATE_WORKING_DRAFT|DRAFT_ONLY_TAXONOMY|draft-only/,
			);
		}
		expect((await call('/api/v2/entries/200?preview=true')).status).toBe(404);
		expect((await call('/practices/200')).status).toBe(404);
	});
	it('keeps new v1 writes and receipts atomic while avoiding native reserved IDs and deleted high-water IDs', async () => {
		await env.DB.prepare('INSERT INTO CatalogEntries (practice_id) VALUES (1000)').run();
		await env.DB.prepare('DELETE FROM CatalogEntries WHERE practice_id = 1000').run();
		await env.DB.batch([
			env.DB.prepare("INSERT INTO Categories (category_id, name) VALUES (1, 'Fixture')"),
			env.DB.prepare("INSERT INTO CloudflareFeatures (feature_id, name) VALUES (1, 'Fixture')"),
		]);
		const payload = validatePractice({
			title: 'Creation fixture',
			description: 'Creation fixture.',
			domain: 'General',
			category_id: 1,
			feature_id: 1,
			recommendation_level: 'Recommended',
			impact_level: 'Low',
			source_reference: 'https://developers.cloudflare.com/',
		});
		const id = await createPractice(env.DB, payload, 'fixture-actor', 'fixture-upgrade-key');
		expect(id).toBe(1001);
		expect(await createPractice(env.DB, payload, 'fixture-actor', 'fixture-upgrade-key')).toBe(id);
		expect((await (await call(`/api/v2/entries/${id}`)).json()).data.type).toBe('legacy-practice');
	});
});

describe('publication storage invariants', () => {
	it('requires a publication of the same entry before setting a public pointer', async () => {
		const row = await env.DB.prepare('SELECT revision_id FROM CatalogRevisions WHERE practice_id = 200').first();
		await expect(
			env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = 200').bind(row.revision_id).run(),
		).rejects.toThrow();
		const published = await env.DB.prepare('SELECT published_revision_id FROM CatalogEntries WHERE practice_id = 100').first();
		await expect(
			env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = 200')
				.bind(published.published_revision_id)
				.run(),
		).rejects.toThrow();
	});
	it('freezes published bodies, sources, taxonomy and history', async () => {
		const { published_revision_id: revision } = await env.DB.prepare(
			'SELECT published_revision_id FROM CatalogEntries WHERE practice_id = 100',
		).first();
		for (const sql of [
			'UPDATE CatalogRevisions SET title = title WHERE revision_id = ?',
			'DELETE FROM CatalogRevisions WHERE revision_id = ?',
			'UPDATE CatalogRevisionSources SET title = title WHERE revision_id = ?',
			'DELETE FROM CatalogRevisionSources WHERE revision_id = ?',
			'UPDATE CatalogRevisionTaxa SET slug = slug WHERE revision_id = ?',
			'DELETE FROM CatalogRevisionTaxa WHERE revision_id = ?',
			'UPDATE CatalogPublications SET published_at = published_at WHERE revision_id = ?',
			'DELETE FROM CatalogPublications WHERE revision_id = ?',
		])
			await expect(env.DB.prepare(sql).bind(revision).run()).rejects.toThrow('immutable');
		await expect(env.DB.prepare("INSERT INTO CatalogRevisionTaxa VALUES (?, 'product', 'access')").bind(revision).run()).rejects.toThrow(
			'immutable',
		);
		await expect(
			env.DB.prepare("INSERT INTO CatalogRevisionSources VALUES (?, 1, 'https://example.com/', 'fixture')").bind(revision).run(),
		).rejects.toThrow('immutable');
		await expect(
			env.DB.prepare('INSERT OR REPLACE INTO CatalogRevisions SELECT * FROM CatalogRevisions WHERE revision_id = ?').bind(revision).run(),
		).rejects.toThrow('immutable');
		await expect(
			env.DB.prepare('INSERT OR REPLACE INTO CatalogPublications SELECT * FROM CatalogPublications WHERE revision_id = ?')
				.bind(revision)
				.run(),
		).rejects.toThrow('immutable');
		await expect(
			env.DB.prepare('UPDATE OR REPLACE CatalogRevisions SET revision_id = ? WHERE practice_id = 100 AND revision_id != ?')
				.bind(revision, revision)
				.run(),
		).rejects.toThrow('immutable');
	});
	it('refuses invalid stored bodies rather than returning unvalidated JSON or caching failures', async () => {
		const revision = await storeRevision(500, contentFixture());
		await env.DB.prepare("UPDATE CatalogRevisions SET body_json = '{}' WHERE revision_id = ?").bind(revision).run();
		await env.DB.batch([
			env.DB.prepare("INSERT INTO CatalogPublications VALUES (500, ?, '2026-10-30')").bind(revision),
			env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = 500').bind(revision),
		]);
		const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
		const response = await call('/api/v2/entries/500');
		expect(response.status).toBe(500);
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(await response.json()).toEqual({ success: false, error: 'Internal server error' });
		expect(logged.mock.calls[0][0]).toBeInstanceOf(Error);
	});
	it('rolls back publication batches on incomplete relationships and prevents incidental legacy conversion', async () => {
		const revision = await storeRevision(400, contentFixture());
		await env.DB.prepare('DELETE FROM CatalogRevisionSources WHERE revision_id = ?').bind(revision).run();
		await expect(
			env.DB.batch([
				env.DB.prepare('INSERT INTO CatalogPublications VALUES (400, ?, ?)').bind(revision, '2026-10-30'),
				env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = 400').bind(revision),
			]),
		).rejects.toThrow('Publication requires');
		expect((await call('/api/v2/entries/400')).status).toBe(404);
		await expect(env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = 1 WHERE practice_id = 1').run()).rejects.toThrow(
			'compatibility adapter',
		);
	});
});
