import { describe, expect, it, vi } from 'vitest';
import pilots from './fixtures/pilots.json';
import { validateContent } from '../src/content/validation';
import { entryMarkdown, fencedCode } from '../src/content/markdown';
import { readingSections } from '../src/content/presentation';
import { normalizeContentRequest } from '../src/public-content';
import { documentPath, markdownPath } from '../src/modules/catalog/document-state';
import { loadListingPage } from '../src/modules/catalog/listing-page';
import { finalizeDocument } from '../src/platform/content-response';

const ORIGIN = 'https://catalog.example.com';
describe('catalog document state', () => {
	it('retains meaningful listing state and removes tracking/defaults before cache lookup', () => {
		const input = new Request(`${ORIGIN}/catalog?tracking=x&q=%20origin%20&sort=title&page=02&pageSize=999&family=cloudflare-one`);
		const normalized = normalizeContentRequest(input);
		expect(normalized.url).toBe(`${ORIGIN}/catalog?q=origin&family=cloudflare-one&page=2&pageSize=50`);
		expect(normalizeContentRequest(normalized).url).toBe(normalized.url);
		expect(documentPath(new URL(normalized.url))).toBe('/catalog?q=origin&family=cloudflare-one&page=2&pageSize=50');
		expect(markdownPath(new URL(normalized.url))).toBe('/catalog.md?q=origin&family=cloudflare-one&page=2&pageSize=50');
	});
	it('locks family hubs to the path while preserving result state for both formats', () => {
		for (const suffix of ['', '.md']) {
			const normalized = normalizeContentRequest(
				new Request(`${ORIGIN}/families/cloudflare-one${suffix}?family=application-services&q=browser&page=2&preview=true`),
			);
			expect(normalized.url).toBe(`${ORIGIN}/families/cloudflare-one${suffix}?q=browser&page=2`);
			expect(markdownPath(new URL(normalized.url))).toBe('/families/cloudflare-one.md?q=browser&page=2');
		}
	});
	it('keeps old document query stripping and normalized representation preferences', () => {
		for (const path of ['/', '/practices/18', '/practices/18.md']) {
			const request = normalizeContentRequest(
				new Request(`${ORIGIN}${path}?q=x&preview=true`, { method: 'HEAD', headers: { Accept: 'text/html;q=.2,text/markdown;q=1' } }),
			);
			expect(request.url).toBe(`${ORIGIN}${path}`);
			expect(request.method).toBe('GET');
			expect(request.headers.get('Accept')).toBe('text/markdown');
		}
	});
	it('preserves query state on data errors and marks the page unavailable before rendering', async () => {
		const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
		try {
			const error = new Error('Fixture D1 failure');
			const state = await loadListingPage(
				{
					prepare() {
						throw error;
					},
				},
				new URL(`${ORIGIN}/catalog?q=preserved`),
			);
			expect(state.status).toBe(503);
			expect(state.query.q).toBe('preserved');
			expect(logged).toHaveBeenCalledWith(error);
		} finally {
			logged.mockRestore();
		}
	});
});

describe('typed pilot presentation', () => {
	it.each(pilots.map((p) => [p.type, p]))('validates the authored %s pilot and exposes all essential sections in Markdown', (_, pilot) => {
		const content = validateContent(pilot);
		const entry = {
			...content,
			lifecycle: { state: 'active', reason: null, supersededBy: null },
			practiceId: 800001,
			revisionId: 42,
			canonicalPath: '/practices/800001',
		};
		const sections = readingSections(content);
		const markdown = entryMarkdown(entry);
		expect(sections.map((s) => s.id)).toEqual(expect.arrayContaining(['validation', 'rollback']));
		for (const section of sections) expect(markdown).toContain(`## ${section.title}`);
		expect(markdown).toContain('Revision: 42');
		expect(markdown).toContain('Fact verified: 2026-10-30');
	});
	it('uses a longer code fence than any stored backtick run and rejects unsafe language markers', () => {
		expect(fencedCode('`````\n</script>', 'typescript')).toBe('``````typescript\n`````\n</script>\n``````\n');
		expect(fencedCode('value', 'text\n# injected')).toBe('```text\nvalue\n```\n');
	});
});

describe('post-adapter document policy', () => {
	it('restores established cache/security policy without buffering streamed HTML or retaining shell validators', () => {
		const rendered = new Response('<h1>SSR</h1>', {
			headers: { 'Content-Type': 'text/html', 'Cloudflare-CDN-Cache-Control': 'no-store', ETag: 'shell', 'Last-Modified': 'shell' },
		});
		const response = finalizeDocument(rendered, '/catalog?q=origin', '/catalog.md?q=origin');
		expect(response.body).toBe(rendered.body);
		expect(response.headers.get('Cloudflare-CDN-Cache-Control')).toContain('max-age=3600');
		expect(response.headers.get('Cache-Tag')).toBe('practices');
		expect(response.headers.get('Vary')).toBe('Accept');
		expect(response.headers.get('Content-Signal')).toBe('search=yes, ai-input=yes, ai-train=no');
		expect(response.headers.get('ETag')).toBeNull();
		expect(response.headers.get('Last-Modified')).toBeNull();
	});
	it.each([{ status: 404 }, { status: 503 }, { headers: { 'Set-Cookie': 'private=fixture' } }])(
		'never shared-caches errors or cookies: %j',
		(init) => {
			const response = finalizeDocument(
				new Response('Fixture', { ...init, headers: { ...init.headers, 'Cache-Tag': 'old', Link: 'old' } }),
				'/catalog',
				'/catalog.md',
			);
			expect(response.headers.get('Cache-Control')).toBe('no-store');
			expect(response.headers.get('Cloudflare-CDN-Cache-Control')).toBe('no-store');
			expect(response.headers.get('X-Robots-Tag')).toBe('noindex');
			expect(response.headers.get('Cache-Tag')).toBeNull();
			expect(response.headers.get('Link')).toBeNull();
		},
	);
});
