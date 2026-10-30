import { listAllPractices } from './modules/catalog/queries';
import { HttpError } from './http';
import { getCatalogEntry } from './modules/catalog/v2-queries';
import { documentPath, isCatalogListing, listingSearch, markdownPath } from './modules/catalog/document-state';
import { agentIndex, catalogMarkdown, listingMarkdown, sitemap, textStream } from './modules/catalog/documents';
import { entryMarkdown } from './content/markdown';
import { CONTENT_HEADERS, contentResponse as response } from './platform/content-response';
import { prefersMarkdown } from './content-negotiation';
import { collectionSchema, homeRows, jsonLd, practiceHtml } from './content-rendering';

export { CONTENT_CACHE_TAG } from './platform/cache';

export function isPublicContent(path: string): boolean {
	return (
		isCatalogListing(path) ||
		['/', '/index.md', '/llms.txt', '/llms-full.txt', '/sitemap.xml', '/api-docs'].includes(path) ||
		/^\/practices\/[1-9]\d*(?:\.md)?$/.test(path)
	);
}

export function normalizeContentRequest(request: Request): Request {
	const url = new URL(request.url);
	// Existing document URLs still drop UI state. Only new listings retain effective state.
	url.search = isCatalogListing(url.pathname) ? listingSearch(url) : '';
	const headers = new Headers(request.headers);
	headers.set('Accept', prefersMarkdown(headers.get('Accept')) ? 'text/markdown' : 'text/html');
	return new Request(url, { method: 'GET', headers });
}

export function contentError(status: number): Response {
	return new Response(
		status === 404
			? 'Practice not found. Browse / or /llms.txt for current practices.'
			: 'Content is temporarily unavailable. Please retry.',
		{
			status,
			headers: { ...CONTENT_HEADERS, 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' },
		},
	);
}

export async function servePublicContent(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);
	const path = url.pathname;
	if (path === '/api-docs') {
		const markdown = prefersMarkdown(request.headers.get('Accept'));
		const asset = await env.ASSETS.fetch(new Request(`${url.origin}/api-docs${markdown ? '.md' : ''}`));
		if (!asset.ok) throw new Error(`API documentation failed: ${asset.status}`);
		return response(asset.body!, markdown ? 'text/markdown' : 'text/html', '/api-docs', '/api-docs.md', true);
	}
	const db = env.DB.withSession('first-primary');
	if (isCatalogListing(path)) {
		if (path.endsWith('.md') || prefersMarkdown(request.headers.get('Accept'))) {
			try {
				return response(await listingMarkdown(db, url), 'text/markdown', documentPath(url), markdownPath(url), !path.endsWith('.md'));
			} catch (err) {
				if (err instanceof HttpError && err.status === 404) return contentError(404);
				throw err;
			}
		}
		return contentError(503); // HTML is supplied by astro-reads, never a second native renderer.
	}
	const match = /^\/practices\/([1-9]\d*)(\.md)?$/.exec(path);
	if (match) {
		const id = Number(match[1]);
		if (!Number.isSafeInteger(id) || id > 2147483647) return contentError(404);
		let entry;
		try {
			entry = (await getCatalogEntry(db, new URL(`/api/v2/entries/${id}`, url))).data;
		} catch (err) {
			if (err instanceof HttpError && err.status === 404) return contentError(404);
			throw err;
		}
		const canonical = `/practices/${id}`;
		const markdown = !!match[2] || prefersMarkdown(request.headers.get('Accept'));
		if (!markdown && entry.schemaVersion !== 0) return contentError(503);
		const body = markdown ? entryMarkdown(entry) : entry.schemaVersion === 0 ? practiceHtml(entry.body) : '';
		return response(body, markdown ? 'text/markdown' : 'text/html', canonical, `${canonical}.md`, !match[2]);
	}
	if (path === '/sitemap.xml') return response(textStream(sitemap(db)), 'application/xml', '/', '/index.md');
	if (path === '/llms.txt') return response(textStream(agentIndex(db)), 'text/plain', '/', '/index.md');
	if (path !== '/' || prefersMarkdown(request.headers.get('Accept'))) {
		return response(textStream(catalogMarkdown(db)), 'text/markdown', '/', '/index.md', path === '/');
	}

	// Keep the framework-independent legacy shell for the domain/gateway regression suite.
	// The production build renders the homepage through Astro in astro-reads.ts.
	const practices = await listAllPractices(db);
	const template = await env.ASSETS.fetch(new Request(`${url.origin}/`));
	if (!template.ok) throw new Error(`Homepage template failed: ${template.status}`);
	const document = new HTMLRewriter()
		.on('#rows', {
			element(el) {
				el.setInnerContent(homeRows(practices), { html: true });
				el.removeAttribute('aria-busy');
			},
		})
		.on('#summary', {
			element(el) {
				el.setInnerContent(`${practices.length} practices`);
			},
		})
		.on('#collection-schema', {
			element(el) {
				el.replace(jsonLd(collectionSchema(practices)), { html: true });
			},
		})
		.transform(template);
	return response(document.body!, 'text/html', '/', '/index.md', true);
}
