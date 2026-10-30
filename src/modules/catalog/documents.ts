import { catalogFacets, getCatalogEntry, listCatalog } from './v2-queries';
import { catalogSummary, type CatalogRow } from './v2-projection';
import { listingState, documentPath } from './document-state';
import { entryMarkdown, markdownText } from '../../content/markdown';
import { HttpError } from '../../http';
import { starterCollection } from './starter-collections';
import { CONTENT_CACHE_TAG } from '../../platform/cache';
import { DISCLAIMER, SITE_NAME, SITE_DESCRIPTION, SITE_URL, escapeHtml, modifiedDate } from '../../content-rendering';

export { CONTENT_CACHE_TAG };

// Keyset iteration bounds each D1 read and keeps bodies out of discovery queries.
export async function* publishedSummaries(db: D1DatabaseSession) {
	let after = 0;
	for (;;) {
		const page = await db
			.prepare('SELECT * FROM PublishedCatalog WHERE practice_id > ? ORDER BY practice_id LIMIT 100')
			.bind(after)
			.all<CatalogRow>();
		for (const row of page.results) yield catalogSummary(row);
		if (page.results.length < 100) return;
		after = page.results.at(-1)!.practice_id;
	}
}

export function textStream(parts: AsyncIterable<string>): ReadableStream<Uint8Array> {
	const iterator = parts[Symbol.asyncIterator]();
	const encoder = new TextEncoder();
	return new ReadableStream({
		async pull(controller) {
			try {
				const next = await iterator.next();
				if (next.done) controller.close();
				else controller.enqueue(encoder.encode(next.value));
			} catch (err) {
				console.error(err);
				controller.error(err);
			}
		},
		async cancel() {
			await iterator.return?.();
		},
	});
}

export async function* catalogMarkdown(db: D1DatabaseSession) {
	yield `# ${SITE_NAME}\n\n${SITE_DESCRIPTION}\n\n${DISCLAIMER}\n\nPublic reads are anonymous. Browse /catalog or /api/v2/entries for bounded summaries; this full export streams every current published entry.\n\n- [Agent index](${SITE_URL}/llms.txt)\n- [API documentation](${SITE_URL}/api-docs)\n- [OpenAPI](${SITE_URL}/openapi.json)\n\n`;
	for await (const row of publishedSummaries(db)) {
		const { data } = await getCatalogEntry(db, new URL(`${SITE_URL}/api/v2/entries/${row.practiceId}`));
		yield `---\n\n${entryMarkdown(data)}\n`;
	}
}

export async function listingMarkdown(db: D1DatabaseSession, url: URL) {
	const state = listingState(url);
	if (url.pathname.startsWith('/families/')) {
		const { data } = await catalogFacets(db, new URL(`${SITE_URL}/api/v2/facets`));
		if (!state.family || !data.families.some((family) => family.slug === state.family)) throw new HttpError(404, 'Family not found');
	}
	const effective = new URL(url);
	for (const [key, value] of Object.entries(state)) effective.searchParams.set(key, String(value));
	const page = await listCatalog(db, effective);
	const starter =
		url.pathname.startsWith('/families/') && state.page === 1 && !state.q && !state.product && !state.outcome && !state.type
			? await starterCollection(db, state.family)
			: null;
	const start = starter
		? `## Start here: ${markdownText(starter.title)}\n\n${starter.entries.map((entry, index) => `${index + 1}. [${markdownText(entry.title)}](${SITE_URL}${entry.canonicalPath}) — ${markdownText(entry.purpose)}`).join('\n')}\n\n`
		: '';
	const pageLink = (n: number) => {
		const link = new URL(url);
		link.searchParams.set('page', String(n));
		return `${SITE_URL}${documentPath(link)}`;
	};
	return `# Browse the field guide\n\nCanonical URL: ${SITE_URL}${documentPath(url)}\n\n${start}${page.total} matching entries; page ${page.page} of ${page.pages}.\n\n${page.data.map((row) => `- [${markdownText(row.title)}](${SITE_URL}${row.canonicalPath}): ${markdownText(row.summary)}`).join('\n')}\n\n${page.links.previous ? `[Previous](${pageLink(page.page - 1)})` : ''} ${page.links.next ? `[Next](${pageLink(page.page + 1)})` : ''}\n\n${DISCLAIMER}\n`;
}

export async function* sitemap(db: D1DatabaseSession) {
	yield `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${SITE_URL}/</loc></url><url><loc>${SITE_URL}/catalog</loc></url><url><loc>${SITE_URL}/api-docs</loc></url>`;
	const facets = await catalogFacets(db, new URL(`${SITE_URL}/api/v2/facets`));
	for (const family of facets.data.families) yield `<url><loc>${SITE_URL}/families/${family.slug}</loc></url>`;
	for await (const row of publishedSummaries(db)) {
		const date = modifiedDate(row.modifiedAt);
		yield `<url><loc>${SITE_URL}${row.canonicalPath}</loc>${date ? `<lastmod>${escapeHtml(date)}</lastmod>` : ''}</url>`;
	}
	yield '</urlset>';
}

export async function* agentIndex(db: D1DatabaseSession) {
	yield `# ${SITE_NAME}\n\n> ${SITE_DESCRIPTION}\n\n${DISCLAIMER}\n\nPublic reads are anonymous. HTML, Markdown and JSON select the same published revisions. Cite canonical /practices/{id} pages and official sources. Request Accept: text/markdown or append .md. Search and AI answer retrieval are permitted; AI training is not.\n\n## Interfaces\n\n- [Browse](${SITE_URL}/catalog): URL-based summary search and populated family hubs, usable without JavaScript\n- [Full repository Markdown](${SITE_URL}/llms-full.txt): streamed current published entries, including legacy practices\n- [Legacy JSON API](${SITE_URL}/api/practices): unchanged v1-eligible practices only\n- [Published summaries](${SITE_URL}/api/v2/entries): q searches title/summary; family/product/outcome/type filters; bounded page/pageSize; links.next and detailPath\n- [Published facets](${SITE_URL}/api/v2/facets): conjunctive populated counts\n- [v2 schema](${SITE_URL}/openapi-v2.json): schemaVersion 0 legacy and version 1 typed bodies; canonicalPath is the HTML citation URL\n- [API documentation](${SITE_URL}/api-docs)\n- [OpenAPI schema](${SITE_URL}/openapi.json)\n- [Authentication guidance](${SITE_URL}/auth.md): anonymous reads; Access-protected dashboard writes only\n- [Agent skill](${SITE_URL}/.well-known/agent-skills/read-practices/SKILL.md)\n\n## Published guidance\n\n`;
	for await (const row of publishedSummaries(db))
		yield `- [${markdownText(row.title)}](${SITE_URL}${row.canonicalPath}): ${markdownText(row.type)}\n`;
}
