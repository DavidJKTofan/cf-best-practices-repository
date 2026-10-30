import { HttpError } from '../../http';
import { getPractice } from './queries';
import { catalogQuery, catalogSearch, type CatalogQuery } from './v2-filters';
import { catalogSummary, legacyDetail, typedDetail, type CatalogRow, type RevisionBodyRow } from './v2-projection';

function filters(query: CatalogQuery) {
	const conditions: string[] = [];
	const bindings: string[] = [];
	if (query.q) {
		// Literal substring, not LIKE: %/_/backslashes are ordinary text and long
		// multibyte input cannot hit D1's 50-byte pattern limit. SQLite lower() is ASCII.
		conditions.push('instr(lower(v.title || char(10) || v.summary), lower(?)) > 0');
		bindings.push(query.q);
	}
	if (query.type) {
		conditions.push('v.content_type = ?');
		bindings.push(query.type);
	}
	for (const kind of ['family', 'product', 'outcome'] as const) {
		if (query[kind]) {
			conditions.push(`EXISTS (SELECT 1 FROM CatalogRevisionTaxa t WHERE t.revision_id = v.revision_id AND t.kind = ? AND t.slug = ?)`);
			bindings.push(kind, query[kind]);
		}
	}
	return { where: conditions.length ? ` WHERE ${conditions.join(' AND ')}` : '', bindings };
}
function pagePath(query: CatalogQuery): string {
	const search = catalogSearch(query);
	return `/api/v2/entries${search ? `?${search}` : ''}`;
}
export async function listCatalog(db: D1DatabaseSession, url: URL) {
	const query = catalogQuery(url);
	const { where, bindings } = filters(query);
	const order = query.sort === 'newest' ? 'v.modified_at DESC, v.practice_id ASC' : 'v.title COLLATE NOCASE ASC, v.practice_id ASC';
	// One batch/snapshot for totals + page; never fetch bodies to list summaries.
	const [count, page] = await db.batch<CatalogRow & { total: number }>([
		db.prepare(`SELECT COUNT(*) AS total FROM PublishedCatalog v${where}`).bind(...bindings),
		db
			.prepare(`SELECT v.* FROM PublishedCatalog v${where} ORDER BY ${order} LIMIT ? OFFSET ?`)
			.bind(...bindings, query.pageSize, (query.page - 1) * query.pageSize),
	]);
	const total = count.results[0].total;
	const pages = Math.ceil(total / query.pageSize);
	return {
		success: true as const,
		data: page.results.map(catalogSummary),
		count: page.results.length,
		total,
		page: query.page,
		pageSize: query.pageSize,
		pages,
		query,
		links: {
			self: pagePath(query),
			next: query.page < pages && query.page < 10000 ? pagePath({ ...query, page: query.page + 1 }) : null,
			previous: query.page > 1 ? pagePath({ ...query, page: query.page - 1 }) : null,
		},
	};
}
export async function getCatalogEntry(db: D1DatabaseSession, url: URL) {
	const id = Number(url.pathname.split('/').at(-1));
	const row = await db.prepare('SELECT * FROM PublishedCatalog WHERE practice_id = ?').bind(id).first<CatalogRow>();
	if (!row) throw new HttpError(404, 'Catalog entry not found');
	if (row.revision_id === null) {
		const practice = await getPractice(db, id);
		if (!practice) throw new Error('Missing published legacy practice');
		return { success: true as const, data: legacyDetail(row, practice) };
	}
	const revision = await db
		.prepare('SELECT applicability_json, body_json FROM CatalogRevisions WHERE practice_id = ? AND revision_id = ?')
		.bind(id, row.revision_id)
		.first<RevisionBodyRow>();
	if (!revision) throw new Error('Missing published revision');
	const sources = await db
		.prepare('SELECT url, title FROM CatalogRevisionSources WHERE revision_id = ? ORDER BY position')
		.bind(row.revision_id)
		.all<{ url: string; title: string }>();
	// Invalid stored content is an operational 500, never a user-input 400 or raw JSON.
	try {
		return { success: true as const, data: typedDetail(row, revision, sources.results) };
	} catch (error) {
		throw new Error('Invalid published catalog revision', { cause: error });
	}
}
export async function catalogFacets(db: D1DatabaseSession, url: URL) {
	const { where, bindings } = filters(catalogQuery(url));
	const [types, taxa] = await db.batch<{ kind: string; slug: string; label: string; count: number }>([
		db
			.prepare(
				`SELECT v.content_type AS slug, COUNT(*) AS count FROM PublishedCatalog v${where} GROUP BY v.content_type ORDER BY v.content_type`,
			)
			.bind(...bindings),
		db
			.prepare(
				`SELECT t.kind, t.slug, x.label, COUNT(*) AS count FROM PublishedCatalog v
			JOIN CatalogRevisionTaxa t ON t.revision_id = v.revision_id
			JOIN CatalogTaxa x ON x.kind = t.kind AND x.slug = t.slug${where}
			GROUP BY t.kind, t.slug, x.label ORDER BY t.kind, t.slug`,
			)
			.bind(...bindings),
	]);
	return {
		success: true as const,
		data: {
			types: types.results.map(({ slug, count }) => ({ slug, count })),
			families: taxa.results.filter((row) => row.kind === 'family').map(({ slug, label, count }) => ({ slug, label, count })),
			products: taxa.results.filter((row) => row.kind === 'product').map(({ slug, label, count }) => ({ slug, label, count })),
			outcomes: taxa.results.filter((row) => row.kind === 'outcome').map(({ slug, label, count }) => ({ slug, label, count })),
		},
	};
}
