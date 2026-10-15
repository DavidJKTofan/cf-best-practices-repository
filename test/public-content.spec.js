import { env } from 'cloudflare:workers';
import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import worker from '../src/index.js';
import { prefersMarkdown } from '../src/content-negotiation';
import { normalizeContentRequest } from '../src/public-content';

const ORIGIN = 'https://db.automatic-demo.com';
const ID = 901001;
const TITLE = 'Protect <API> & clients </script><script>alert(1)</script>';
const CONFIG = 'http.host eq "example.com"\n```\n<script>not executable</script>';

async function call(path, init = {}, overrides = {}) {
	const ctx = createExecutionContext();
	const response = await worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...overrides }, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

beforeAll(async () => {
	await env.DB.prepare(
		`INSERT INTO BestPractices (practice_id, title, description, domain, prerequisites,
		expressions_configuration_details, source_reference, notes, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
		.bind(
			ID,
			TITLE,
			'Throttle abusive API clients without a browser challenge.',
			'Security',
			'Verify your plan entitlement.',
			CONFIG,
			'https://developers.cloudflare.com/waf/',
			'Observe matches before enforcement.',
			'2026-10-14 10:00:00',
		)
		.run();
});

describe('content negotiation', () => {
	it('normalizes equivalent requests before caching and removes UI-only query state', () => {
		for (const accept of ['text/markdown', 'text/html;q=0.5,text/markdown;q=1']) {
			const request = normalizeContentRequest(new Request(`${ORIGIN}/?q=WAF&sort=title`, { method: 'HEAD', headers: { Accept: accept } }));
			expect(request.url).toBe(`${ORIGIN}/`);
			expect(request.headers.get('Accept')).toBe('text/markdown');
			expect(request.method).toBe('GET');
		}
	});
	it.each([
		[null, false],
		['*/*', false],
		['text/*', false],
		['text/html', false],
		['text/markdown', true],
		['TEXT/MARKDOWN; charset=utf-8', true],
		['text/html, text/markdown', true],
		['text/html;q=0.8, text/markdown;q=0.9', true],
		['text/html, text/markdown;q=0.5', false],
		['text/markdown;q=0, */*', false],
		['text/markdown;q=bogus', false],
		['text/markdown;q=0.9, text/*;q=1', false],
	])('Accept %s selects Markdown: %s', (accept, expected) => {
		expect(prefersMarkdown(accept)).toBe(expected);
	});
});

describe('crawlable public documents', () => {
	it('renders practice links, descriptions and collection metadata in the initial HTML', async () => {
		const response = await call('/?q=WAF&sort=title');
		expect(response.status).toBe(200);
		expect(response.headers.get('Content-Type')).toContain('text/html');
		expect(response.headers.get('Vary')).toBe('Accept');
		expect(response.headers.get('X-Robots-Tag')).toBeNull();
		expect(response.headers.get('ETag')).toBeNull();
		expect(response.headers.get('Last-Modified')).toBeNull();
		const html = await response.text();
		expect(html).toContain(`href="/practices/${ID}"`);
		expect(html).toContain('Throttle abusive API clients');
		expect(html).not.toContain('class="skeleton"');
		const schemas = [...html.matchAll(/<script type="application\/ld\+json">(.*?)<\/script>/gs)].map((match) => JSON.parse(match[1]));
		expect(schemas.some((schema) => schema['@type'] === 'CollectionPage')).toBe(true);
		expect(html).not.toContain('</script><script>alert(1)</script>');
	});

	it('serves complete Markdown on the homepage with discovery and cache headers', async () => {
		const response = await call('/', { headers: { Accept: 'text/markdown' } });
		expect(response.headers.get('Content-Type')).toBe('text/markdown; charset=utf-8');
		expect(response.headers.get('Vary')).toBe('Accept');
		expect(response.headers.get('Content-Signal')).toContain('ai-input=yes');
		expect(response.headers.get('Link')).toContain('rel="api-catalog"');
		expect(response.headers.get('Link')).toContain('rel="alternate"; type="text/markdown"');
		expect(response.headers.get('Cache-Tag')).toBe('practices');
		const markdown = await response.text();
		expect(markdown).toContain(`Canonical URL: ${ORIGIN}/practices/${ID}`);
		expect(markdown).toContain(CONFIG);
		expect(markdown).toContain('Verify your plan entitlement');
		expect(markdown).toContain('https://developers.cloudflare.com/waf/');
		expect(markdown).toContain('````text');
	});

	it('uses explicit Markdown URLs independently of Accept and keeps HTML/Markdown variants distinct', async () => {
		for (const path of ['/index.md', '/llms-full.txt', `/practices/${ID}.md`]) {
			const response = await call(path, { headers: { Accept: 'text/html' } });
			expect(response.status).toBe(200);
			expect(response.headers.get('Content-Type')).toContain('text/markdown');
			expect(await response.text()).toContain(CONFIG);
		}
		for (const accept of ['text/html', 'text/markdown', 'text/html']) {
			const response = await call(`/practices/${ID}`, { headers: { Accept: accept } });
			expect(response.headers.get('Content-Type')).toContain(accept);
			expect(response.headers.get('Vary')).toBe('Accept');
		}
	});

	it('renders escaped detail text, safe sources, real dates, and parseable article metadata', async () => {
		const response = await call(`/practices/${ID}`);
		const html = await response.text();
		expect(html).toContain('Protect &lt;API&gt; &amp; clients');
		expect(html).not.toContain('<script>alert(1)</script>');
		expect(html).toContain('&lt;script&gt;not executable&lt;/script&gt;');
		expect(html).toContain('datetime="2026-10-14T10:00:00.000Z"');
		expect(html).toContain(`<link rel="canonical" href="${ORIGIN}/practices/${ID}">`);
		const schemas = [...html.matchAll(/<script type="application\/ld\+json">(.*?)<\/script>/gs)].map((match) => JSON.parse(match[1]));
		expect(schemas.find((schema) => schema['@type'] === 'TechArticle')).toMatchObject({
			headline: TITLE,
			citation: 'https://developers.cloudflare.com/waf/',
		});
	});

	it('returns non-cacheable 404 for missing or overflowing IDs, including Markdown URLs', async () => {
		for (const path of ['/practices/2147483647', '/practices/999999999999999999.md']) {
			const response = await call(path);
			expect(response.status).toBe(404);
			expect(response.headers.get('Cache-Control')).toBe('no-store');
		}
	});

	it('never turns legacy non-HTTP source data into active links or structured citations', async () => {
		await env.DB.prepare('INSERT INTO BestPractices (practice_id, title, description, domain, source_reference) VALUES (?, ?, ?, ?, ?)')
			.bind(ID + 1, 'Legacy source', 'Review the recorded source.', 'Security', 'javascript:alert(1)')
			.run();
		for (const accept of ['text/html', 'text/markdown']) {
			const response = await call(`/practices/${ID + 1}`, { headers: { Accept: accept } });
			expect(await response.text()).not.toContain('javascript:');
		}
	});

	it('lists canonical URLs and real modification dates in the sitemap', async () => {
		const response = await call('/sitemap.xml');
		expect(response.headers.get('Content-Type')).toContain('application/xml');
		expect(response.headers.get('Cache-Tag')).toBe('practices');
		const xml = await response.text();
		expect(xml).toContain(`<loc>${ORIGIN}/practices/${ID}</loc><lastmod>2026-10-14T10:00:00.000Z</lastmod>`);
		expect(xml).not.toMatch(/\.md|dashboard|cdn-cgi|<loc>[^<]*\?/);
	});

	it('discovers records and public read instructions without client JavaScript', async () => {
		const response = await call('/llms.txt');
		expect(response.headers.get('Content-Type')).toContain('text/plain');
		const text = await response.text();
		expect(text).toContain(`${ORIGIN}/practices/${ID}`);
		expect(text).toContain('Public reads are anonymous');
		expect(text).toContain('/openapi.json');
	});

	it('negotiates API documentation too', async () => {
		for (const accept of ['text/html', 'text/markdown']) {
			const response = await call('/api-docs', { headers: { Accept: accept } });
			expect(response.status).toBe(200);
			expect(response.headers.get('Content-Type')).toContain(accept);
			expect(response.headers.get('Link')).toContain(`${ORIGIN}/api-docs`);
			expect(await response.text()).toContain('/api/practices');
		}
	});

	it('supports HEAD and CORS preflight without response bodies', async () => {
		for (const path of ['/', `/practices/${ID}`, '/api/practices']) {
			const response = await call(path, { method: 'HEAD', headers: { Accept: 'text/markdown' } });
			expect(response.status).toBe(200);
			expect(await response.text()).toBe('');
			const options = await call(path, { method: 'OPTIONS' });
			expect(options.status).toBe(204);
			expect(options.headers.get('Access-Control-Allow-Methods')).toContain('HEAD');
		}
	});

	it('rate-limits negotiated reads before entering the cached entrypoint', async () => {
		const limit = vi.fn().mockResolvedValue({ success: false });
		const response = await call('/', { headers: { Accept: 'text/markdown' } }, { MY_RATE_LIMITER: { limit } });
		expect(response.status).toBe(429);
		expect(response.headers.get('Retry-After')).toBe('60');
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(limit).toHaveBeenCalledOnce();
	});
});

describe('agent discovery assets', () => {
	const asset = (path) => env.ASSETS.fetch(new Request(`${ORIGIN}${path}`));

	it('publishes a CORS-readable RFC 9727 API catalog linked to the real public schema', async () => {
		const response = await asset('/.well-known/api-catalog');
		expect(response.status).toBe(200);
		expect(response.headers.get('Content-Type')).toContain('application/linkset+json');
		expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
		const { linkset } = await response.json();
		const schemaResponse = await asset(new URL(linkset[0]['service-desc'][0].href).pathname);
		expect(schemaResponse.status).toBe(200);
		const schema = await schemaResponse.json();
		expect(schema.openapi).toBe('3.1.0');
		expect(schema.security).toEqual([]);
		expect(Object.keys(schema.paths)).toEqual(['/api/practices', '/api/categories', '/api/features', '/practices/{id}']);
		expect(schema.paths['/api/practices'].get.parameters.map((p) => p.name)).toEqual([
			'search',
			'categoryId',
			'featureId',
			'area',
			'level',
			'impact',
		]);
	});

	it('publishes a skills index whose digest matches the actual Markdown bytes', async () => {
		const index = await (await asset('/.well-known/agent-skills/index.json')).json();
		expect(index.$schema).toContain('/0.2.0/schema.json');
		for (const skill of index.skills) {
			const response = await asset(new URL(skill.url).pathname);
			expect(response.status).toBe(200);
			expect(response.headers.get('Content-Type')).toContain('text/markdown');
			const hash = await crypto.subtle.digest('SHA-256', await response.arrayBuffer());
			const hex = Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, '0')).join('');
			expect(skill.digest).toBe(`sha256:${hex}`);
		}
	});

	it('advertises real resource URLs and an explicit search/retrieval crawler policy', async () => {
		const catalog = await (await asset('/.well-known/ai-catalog.json')).json();
		for (const entry of catalog.entries) {
			expect(entry.identifier).toMatch(/^urn:air:db\.automatic-demo\.com:/);
			expect(entry.representativeQueries.length).toBeGreaterThanOrEqual(2);
			const response = await call(new URL(entry.url).pathname);
			expect(response.status).toBe(200);
		}
		const robots = await (await asset('/robots.txt')).text();
		expect(robots).toContain('search=yes, ai-input=yes, ai-train=no');
		expect(robots).toContain(`Sitemap: ${ORIGIN}/sitemap.xml`);
		expect(robots).not.toContain('Disallow: /api/');
		expect(robots).toContain('Disallow: /cdn-cgi/');
		expect(robots).toContain('User-agent: OAI-SearchBot');
	});
});
