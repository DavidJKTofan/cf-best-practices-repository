import { afterEach, describe, expect, it, vi } from 'vitest';
import worker, { PublicReads } from '../src/index';

const ORIGIN = 'https://catalog.example.com';

function harness(overrides = {}) {
	const read = vi.fn().mockResolvedValue(new Response('read body', { headers: { 'Cache-Tag': 'practices', Vary: 'Accept' } }));
	const assets = vi.fn().mockResolvedValue(new Response('asset body', { status: 404, headers: { 'X-Asset': 'fallback' } }));
	const limit = vi.fn().mockResolvedValue({ success: true });
	const env = { ASSETS: { fetch: assets }, MY_RATE_LIMITER: { limit }, ...overrides };
	const ctx = { exports: { PublicReads: { fetch: read } } };
	const call = (path, init = {}) => worker.fetch(new Request(`${ORIGIN}${path}`, init), env, ctx);
	return { call, env, ctx, read, assets, limit };
}

afterEach(() => vi.restoreAllMocks());

describe('gateway compatibility boundaries', () => {
	it('normalizes effective API filters before loopback fetch, after rate limiting', async () => {
		const { call, read, limit, assets } = harness();
		await call('/api/practices?unused=x&impact=High&categoryId=01&search=%20rate%00_limit%20', {
			headers: { 'CF-Connecting-IP': '203.0.113.7', Accept: 'application/json' },
		});
		expect(limit).toHaveBeenCalledWith({ key: '203.0.113.7:/api/practices' });
		expect(limit.mock.invocationCallOrder[0]).toBeLessThan(read.mock.invocationCallOrder[0]);
		const [request] = read.mock.calls[0];
		expect(request.url).toBe(`${ORIGIN}/api/practices?search=rate_limit&categoryId=1&impact=High`);
		expect(request.method).toBe('GET');
		expect(request.headers.get('Accept')).toBe('application/json');
		expect(assets).not.toHaveBeenCalled();
	});

	it('normalizes document variants and strips UI queries, but preserves response headers', async () => {
		const { call, read } = harness();
		const response = await call('/practices/18?search=ignored', { headers: { Accept: 'text/html;q=0.2,text/markdown' } });
		const [request] = read.mock.calls[0];
		expect(request.url).toBe(`${ORIGIN}/practices/18`);
		expect(request.headers.get('Accept')).toBe('text/markdown');
		expect(response.headers.get('Vary')).toBe('Accept');
		expect(response.headers.get('Cache-Tag')).toBe('practices');
		expect(await response.text()).toBe('read body');
	});

	it.each(['/api/practices', '/', '/practices/18.md', '/api-docs'])(
		'forwards HEAD as GET and removes only the final body: %s',
		async (path) => {
			const { call, read } = harness();
			const response = await call(path, { method: 'HEAD' });
			expect(read.mock.calls[0][0].method).toBe('GET');
			expect(response.status).toBe(200);
			expect(response.headers.get('Cache-Tag')).toBe('practices');
			expect(await response.text()).toBe('');
		},
	);

	it.each(['/api/practices', '/api/unknown', '/', '/practices/18', '/api-docs'])(
		'answers OPTIONS before route lookup, rate limiting or D1: %s',
		async (path) => {
			const { call, read, limit, assets } = harness();
			const response = await call(path, { method: 'OPTIONS' });
			expect(response.status).toBe(204);
			expect(response.headers.get('Access-Control-Allow-Methods')).toBe('GET, HEAD, OPTIONS');
			expect(await response.text()).toBe('');
			expect(read).not.toHaveBeenCalled();
			expect(limit).not.toHaveBeenCalled();
			expect(assets).not.toHaveBeenCalled();
		},
	);

	it.each(['GET', 'POST', 'OPTIONS', 'HEAD'])('keeps API unknown-path method/error precedence: %s', async (method) => {
		const { call, read, limit } = harness();
		const response = await call('/api/unknown', { method, headers: { 'cf-ray': 'compat-request-id' } });
		if (method === 'OPTIONS') {
			expect(response.status).toBe(204);
		} else {
			expect(response.status).toBe(method === 'POST' ? 405 : 404);
			expect(response.headers.get('Cache-Control')).toBe('no-store');
			expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
			// Characterize the raw handler, including its HEAD error envelope; the HTTP server suppresses HEAD bodies on the wire.
			expect(await response.json()).toEqual({
				success: false,
				error: method === 'POST' ? 'Method not allowed' : 'API endpoint not found',
				requestId: 'compat-request-id',
			});
		}
		expect(read).not.toHaveBeenCalled();
		expect(limit).not.toHaveBeenCalled();
	});

	it.each(['GET', 'OPTIONS', 'HEAD', 'PUT'])('keeps creation POST-only without public CORS: %s', async (method) => {
		const { call, read, assets, limit } = harness();
		const response = await call('/dashboard/api/practices', { method });
		expect(response.status).toBe(405);
		expect(response.headers.get('Allow')).toBe('POST');
		expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect((await response.json()).error).toBe('Method not allowed');
		expect(read).not.toHaveBeenCalled();
		expect(assets).not.toHaveBeenCalled();
		expect(limit).not.toHaveBeenCalled();
	});

	it.each([
		'/api',
		'/API/practices',
		'/%61pi/practices',
		'/dashboard/api/practices/',
		'/dashboard/api/unknown',
		'/practices/018',
		'/practices/18/',
		'/style.css',
	])('preserves exact path matching and unmodified asset fallback: %s', async (path) => {
		const { call, read, assets, limit } = harness();
		const response = await call(path);
		expect(response.status).toBe(404);
		expect(response.headers.get('X-Asset')).toBe('fallback');
		expect(await response.text()).toBe('asset body');
		expect(assets.mock.calls[0][0].url).toBe(`${ORIGIN}${path}`);
		expect(read).not.toHaveBeenCalled();
		expect(limit).not.toHaveBeenCalled();
	});

	it('rejects explicit rate limits before reads and fails open only on limiter outages', async () => {
		vi.spyOn(console, 'error').mockImplementation(() => {});
		const { call, read, limit } = harness();
		limit.mockResolvedValueOnce({ success: false }).mockRejectedValueOnce(new Error('limiter outage'));
		const rejected = await call('/api/practices');
		expect(rejected.status).toBe(429);
		expect(rejected.headers.get('Retry-After')).toBe('60');
		expect(rejected.headers.get('Cache-Control')).toBe('no-store');
		expect(read).not.toHaveBeenCalled();
		expect((await call('/api/practices')).status).toBe(200);
		expect(read).toHaveBeenCalledOnce();
	});

	it('keeps unexpected gateway failures private and non-cacheable', async () => {
		const error = new Error('private failure detail');
		const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
		const { call, read } = harness();
		read.mockRejectedValueOnce(error);
		const response = await call('/api/practices', { headers: { 'cf-ray': 'failure-id' } });
		expect(logged).toHaveBeenCalledWith(error);
		expect(response.status).toBe(500);
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(await response.json()).toEqual({ success: false, error: 'Internal server error', requestId: 'failure-id' });
	});

	it('leaves static assets on the original binding fast path, including async failures', async () => {
		const { call, assets, read } = harness();
		assets.mockRejectedValueOnce(new Error('asset binding unavailable'));
		await expect(call('/style.css')).rejects.toThrow('asset binding unavailable');
		expect(read).not.toHaveBeenCalled();
	});
});

describe('cached entrypoint ownership', () => {
	it('purges only from the cache-owning entrypoint, with an explicit local no-op', async () => {
		const purge = vi.fn().mockResolvedValue({ success: true, errors: [] });
		const reads = new PublicReads({ cache: { purge } }, {});
		expect(await reads.purgePractices()).toEqual({ success: true, errors: [] });
		expect(purge).toHaveBeenCalledWith({ tags: ['practices'] });
		expect(await new PublicReads({}, {}).purgePractices()).toEqual({ success: true, errors: [] });
	});

	it.each(['/api/practices', '/api/categories', '/api/features'])('uses first-primary for read fills: %s', async (path) => {
		const all = vi.fn().mockResolvedValue({ results: [], meta: {} });
		const statement = { all, bind: () => statement };
		const withSession = vi.fn().mockReturnValue({ prepare: () => statement });
		const response = await new PublicReads({}, { DB: { withSession } }).fetch(new Request(`${ORIGIN}${path}`));
		expect(withSession).toHaveBeenCalledWith('first-primary');
		expect(response.status).toBe(200);
		expect(response.headers.get('Cloudflare-CDN-Cache-Control')).toBe('public, max-age=3600, stale-while-revalidate=86400');
		expect(await response.json()).toEqual({ success: true, data: [], count: 0 });
	});

	it.each(['/index.md', '/sitemap.xml', '/llms.txt', '/llms-full.txt', '/practices/18'])(
		'uses first-primary for D1-derived document fills: %s',
		async (path) => {
			const statement = { all: async () => ({ results: [] }), first: async () => null, bind: () => statement };
			const withSession = vi.fn().mockReturnValue({ prepare: () => statement });
			const response = await new PublicReads({}, { DB: { withSession } }).fetch(new Request(`${ORIGIN}${path}`));
			expect(withSession).toHaveBeenCalledWith('first-primary');
			expect(response.status).toBe(path.startsWith('/practices/') ? 404 : 200);
		},
	);

	it('keeps document failures distinct from JSON read failures and logs error objects', async () => {
		const error = new Error('D1 unavailable');
		const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
		const reads = new PublicReads(
			{},
			{
				DB: {
					withSession: () => {
						throw error;
					},
				},
			},
		);
		const api = await reads.fetch(new Request(`${ORIGIN}/api/practices`));
		expect(api.status).toBe(500);
		expect(await api.json()).toEqual({ success: false, error: 'Internal server error' });
		const document = await reads.fetch(new Request(`${ORIGIN}/practices/18`));
		expect(document.status).toBe(503);
		expect(document.headers.get('Content-Type')).toBe('text/plain; charset=utf-8');
		for (const response of [api, document]) {
			expect(response.headers.get('Cache-Control')).toBe('no-store');
			expect(response.headers.get('Cache-Tag')).toBeNull();
			expect(response.headers.get('X-Robots-Tag')).toBe('noindex');
		}
		expect(logged).toHaveBeenCalledWith(error);
	});
});
