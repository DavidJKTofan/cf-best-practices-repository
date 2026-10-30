import { readFile, readdir } from 'node:fs/promises';
import wrangler from 'wrangler';

export const PILOT_IDS = [800001, 800002, 800003]; // Ephemeral test identities, never production reservations.
export const pilots = JSON.parse(await readFile(new URL('../../../test/fixtures/pilots.json', import.meta.url), 'utf8'));
export const starters = JSON.parse(await readFile(new URL('../../../data/phase5/starters.json', import.meta.url), 'utf8'));
const { unstable_splitSqlQuery: split } = wrangler;

export async function storePilot(db, id, c, publish = true) {
	await db.prepare('INSERT OR IGNORE INTO CatalogEntries (practice_id) VALUES (?)').bind(id).run();
	const revision = await db
		.prepare(
			`INSERT INTO CatalogRevisions
		(practice_id, schema_version, content_type, title, summary, primary_family, applicability_json, body_json, evidence, maturity, modified_at, fact_verified_at, review_due_at)
		VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING revision_id`,
		)
		.bind(
			id,
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
	const rid = revision.revision_id;
	const statements = [];
	for (const [kind, slugs] of [
		['family', c.families],
		['product', c.products],
		['outcome', c.outcomes],
	])
		for (const slug of slugs) {
			statements.push(db.prepare('INSERT OR IGNORE INTO CatalogTaxa (kind, slug, label) VALUES (?, ?, ?)').bind(kind, slug, slug));
			statements.push(db.prepare('INSERT INTO CatalogRevisionTaxa (revision_id, kind, slug) VALUES (?, ?, ?)').bind(rid, kind, slug));
		}
	c.sources.forEach((s, index) =>
		statements.push(db.prepare('INSERT INTO CatalogRevisionSources VALUES (?, ?, ?, ?)').bind(rid, index, s.url, s.title)),
	);
	if (publish)
		statements.push(
			db.prepare('INSERT INTO CatalogPublications VALUES (?, ?, ?)').bind(id, rid, '2026-10-30'),
			db.prepare('UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = ?').bind(rid, id),
		);
	await db.batch(statements);
	return rid;
}

export async function seedFrontend(db, { starterCollection = false } = {}) {
	const root = new URL('../../../', import.meta.url);
	const migrations = new URL('migrations/', root);
	for (const file of (await readdir(migrations)).filter((f) => f.endsWith('.sql')).sort()) {
		await db.batch(split(await readFile(new URL(file, migrations), 'utf8')).map((sql) => db.prepare(sql)));
	}
	for (const file of [
		'initial_data.sql',
		'data/copyable-expressions.sql',
		'data/content-review-2026-10-29.sql',
		'data/catalog-taxonomy.sql',
		'data/phase5-products.sql',
	]) {
		await db.batch(split(await readFile(new URL(file, root), 'utf8')).map((sql) => db.prepare(sql)));
	}
	if (starterCollection) {
		const statements = split(await readFile(new URL('data/phase5/local-starters.sql', root), 'utf8'));
		await db.batch(statements.map((sql) => db.prepare(sql)));
		return;
	}
	for (const [i, content] of pilots.entries()) await storePilot(db, PILOT_IDS[i], content);
	await storePilot(db, PILOT_IDS[0], { ...pilots[0], title: 'PRIVATE_REVISION_CANARY' }, false);
	await storePilot(db, 800004, { ...pilots[0], title: 'PRIVATE_ENTRY_CANARY', products: ['private-canary'] }, false);
	await db
		.prepare('INSERT INTO CatalogDrafts (practice_id, content_json) VALUES (?, ?)')
		.bind(PILOT_IDS[0], '{"title":"PRIVATE_DRAFT_CANARY"}')
		.run();
}

export function frontendHarness(vars = {}) {
	return wrangler.createTestHarness({ workers: [{ configPath: './dist/server/wrangler.json', vars }] });
}
