import { catalogSummary, type CatalogRow } from './v2-projection';

// Editorial reading order, not another body authority or a production ID allocator.
// Exact reviewed titles + family select only active PublishedCatalog summaries.
// Hide the collection if either title is missing/renamed/ambiguous, never fill it
// from a private draft or guess a replacement. Review selectors after publication.
const COLLECTIONS: Record<string, { title: string; entries: { title: string; purpose: string }[] }> = {
	'cloudflare-one': {
		title: 'Protect the path. Rehearse its recovery.',
		entries: [
			{ title: 'Stage an Access-protected Tunnel hostname without opening the origin', purpose: '01 / Implement the trust boundary' },
			{ title: 'Diagnose a Tunnel 502 without weakening Access or origin TLS', purpose: '02 / Recover without bypassing it' },
		],
	},
	'developer-platform': {
		title: 'Bound the read. Make recovery deliberate.',
		entries: [
			{ title: 'Read D1 summaries with bounded keyset pagination', purpose: '01 / Implement a bounded read' },
			{ title: 'Recover an uncertain D1 write without creating a duplicate', purpose: '02 / Rehearse uncertain outcomes' },
		],
	},
};

export async function starterCollection(db: D1DatabaseSession, family: string) {
	if (!Object.hasOwn(COLLECTIONS, family)) return null;
	const collection = COLLECTIONS[family];
	const rows = await db
		.prepare(
			`SELECT * FROM PublishedCatalog WHERE schema_version = 1 AND content_type = 'implementation-guide' AND primary_family = ?
		AND json_extract(lifecycle_json, '$.state') = 'active' AND title IN (?, ?) LIMIT 3`,
		)
		.bind(family, ...collection.entries.map((entry) => entry.title))
		.all<CatalogRow>();
	if (rows.results.length !== collection.entries.length) return null;
	const entries = collection.entries.map((entry) => {
		const matches = rows.results.filter((row) => row.title === entry.title);
		return matches.length === 1 ? { ...catalogSummary(matches[0]), purpose: entry.purpose } : null;
	});
	if (entries.some((entry) => entry === null)) return null;
	return { title: collection.title, entries: entries.filter((entry) => entry !== null) };
}
