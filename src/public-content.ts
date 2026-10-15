import { PRACTICES_SQL, type Practice } from './practice-data';
import { prefersMarkdown } from './content-negotiation';
import {
	SITE_URL,
	SITE_NAME,
	CONTENT_SIGNAL,
	DISCLAIMER,
	collectionMarkdown,
	collectionSchema,
	discoveryLinks,
	homeRows,
	jsonLd,
	modifiedDate,
	practiceHtml,
	practiceMarkdown,
} from './content-rendering';

export const CONTENT_CACHE_TAG = 'practices';
const EDGE_TTL = 'public, max-age=3600, stale-while-revalidate=86400';
const CONTENT_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'",
	'Content-Language': 'en',
	'Content-Signal': CONTENT_SIGNAL,
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
	'Access-Control-Expose-Headers': 'Link, Content-Signal, Content-Location',
	'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
};

export function isPublicContent(path: string): boolean {
	return (
		['/', '/index.md', '/llms.txt', '/llms-full.txt', '/sitemap.xml', '/api-docs'].includes(path) ||
		/^\/practices\/[1-9]\d*(?:\.md)?$/.test(path)
	);
}

export function normalizeContentRequest(request: Request): Request {
	const url = new URL(request.url);
	// The browser applies table state; it must not multiply identical cached documents.
	url.search = '';
	const headers = new Headers(request.headers);
	headers.set('Accept', prefersMarkdown(headers.get('Accept')) ? 'text/markdown' : 'text/html');
	return new Request(url, { method: 'GET', headers });
}

function response(body: BodyInit, type: string, canonical: string, markdown: string, vary = false): Response {
	return new Response(body, {
		headers: {
			...CONTENT_HEADERS,
			'Content-Type': `${type}; charset=utf-8`,
			'Cache-Control': 'public, max-age=60, stale-while-revalidate=600',
			'Cloudflare-CDN-Cache-Control': EDGE_TTL,
			'Cache-Tag': CONTENT_CACHE_TAG,
			Link: discoveryLinks(canonical, markdown),
			...(vary ? { Vary: 'Accept' } : {}),
		},
	});
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
	const match = /^\/practices\/([1-9]\d*)(\.md)?$/.exec(path);
	if (match) {
		const id = Number(match[1]);
		if (!Number.isSafeInteger(id) || id > 2147483647) return contentError(404);
		const practice = await db.prepare(`${PRACTICES_SQL} WHERE bp.practice_id = ?`).bind(id).first<Practice>();
		if (!practice) return contentError(404);
		const canonical = `/practices/${id}`;
		const markdown = !!match[2] || prefersMarkdown(request.headers.get('Accept'));
		return response(
			markdown ? `${practiceMarkdown(practice)}\n---\n\n${DISCLAIMER}\n` : practiceHtml(practice),
			markdown ? 'text/markdown' : 'text/html',
			canonical,
			`${canonical}.md`,
			!match[2],
		);
	}

	const { results: practices } = await db.prepare(`${PRACTICES_SQL} ORDER BY bp.domain, category_name, bp.title`).all<Practice>();
	if (path === '/sitemap.xml') {
		const entries = [
			`<url><loc>${SITE_URL}/</loc></url>`,
			`<url><loc>${SITE_URL}/api-docs</loc></url>`,
			...practices.map((p) => {
				const updated = modifiedDate(p.updated_at);
				return `<url><loc>${SITE_URL}/practices/${p.practice_id}</loc>${updated ? `<lastmod>${updated}</lastmod>` : ''}</url>`;
			}),
		];
		return response(
			`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${entries.join('')}</urlset>`,
			'application/xml',
			'/',
			'/index.md',
		);
	}
	if (path === '/llms.txt') {
		const text = `# ${SITE_NAME}\n\n> Sourced Cloudflare application security, performance, and reliability recommendations.\n\n${DISCLAIMER}\n\nPublic reads are anonymous. HTML and Markdown contain the same records; request Accept: text/markdown on / or /practices/{id}, or append .md to a practice URL. Cite canonical HTML URLs and their official source links. Search and AI answer retrieval are permitted; AI training is not.\n\n## Interfaces\n\n- [Full repository Markdown](${SITE_URL}/llms-full.txt): all practice details\n- [JSON API](${SITE_URL}/api/practices): filters search, categoryId, featureId, area, level, impact; returns success, data, count\n- [API documentation](${SITE_URL}/api-docs)\n- [OpenAPI schema](${SITE_URL}/openapi.json)\n- [Authentication guidance](${SITE_URL}/auth.md): no login for reads; dashboard writes require Cloudflare Access\n- [Agent skill](${SITE_URL}/.well-known/agent-skills/read-practices/SKILL.md)\n\n## Practices\n\n${practices.map((p) => `- [${p.title.replace(/[\[\]\\\r\n]/g, ' ')}](${SITE_URL}/practices/${p.practice_id}): ${p.domain}`).join('\n')}\n`;
		return response(text, 'text/plain', '/', '/index.md');
	}
	if (path !== '/' || prefersMarkdown(request.headers.get('Accept'))) {
		return response(collectionMarkdown(practices), 'text/markdown', '/', '/index.md', path === '/');
	}

	// Stream the static shell through HTMLRewriter. Only escaped HTML is inserted; no API data reaches innerHTML.
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
	// Template validators describe the shell, not this D1-derived document; do not forward them.
	return response(document.body!, 'text/html', '/', '/index.md', true);
}
