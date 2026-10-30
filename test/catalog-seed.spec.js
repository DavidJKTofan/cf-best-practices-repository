import { env } from 'cloudflare:workers';
import { beforeAll, expect, it } from 'vitest';
import { PublicReads } from '../src/index';

beforeAll(async () => {
	await env.DB.batch(env.TEST_CATALOG_SQL.map((sql) => env.DB.prepare(sql)));
});

it('serves and validates every real public seed/patch body through the same v2 detail boundary', async () => {
	const reads = new PublicReads({}, env);
	let path = '/api/v2/entries?pageSize=50';
	const seen = new Set();
	while (path) {
		const response = await reads.fetch(new Request(`https://catalog.example.com${path}`));
		expect(response.status).toBe(200);
		const page = await response.json();
		for (const summary of page.data) {
			expect(seen.has(summary.practiceId)).toBe(false);
			seen.add(summary.practiceId);
			const detail = await reads.fetch(new Request(`https://catalog.example.com${summary.detailPath}`));
			expect(detail.status).toBe(200);
			expect((await detail.json()).data).toMatchObject(summary);
		}
		path = page.links.next;
		if (!path) expect(seen.size).toBe(page.total);
	}
	expect(seen.size).toBeGreaterThanOrEqual(119);
});

it('contains no private drafts, receipts, unreferenced revisions, or draft-only IDs in the public seed', async () => {
	for (const table of ['CatalogDrafts', 'PracticeCreations']) {
		expect((await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first()).count).toBe(0);
	}
	expect(
		(await env.DB.prepare('SELECT revision_id FROM CatalogRevisions EXCEPT SELECT published_revision_id FROM CatalogEntries').all())
			.results,
	).toEqual([]);
	expect(
		(
			await env.DB.prepare(
				'SELECT practice_id FROM CatalogEntries WHERE legacy_practice_id IS NULL AND published_revision_id IS NULL',
			).all()
		).results,
	).toEqual([]);
});
