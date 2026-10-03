import { env } from 'cloudflare:workers';
import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import worker from '../src/index.js';

const ORIGIN = 'https://db.automatic-demo.com';

const VALID_PRACTICE = {
	title: '  Enable WAF  ',
	description: 'Deploy the managed ruleset.',
	domain: 'Security',
	category_id: '1',
	feature_id: 1,
	recommendation_level: 'Recommended',
	impact_level: 'High',
	difficulty_level: 'Easy',
	source_reference: 'https://developers.cloudflare.com/waf/',
};

async function call(path, init = {}, envOverrides = {}) {
	const ctx = createExecutionContext();
	const response = await worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...envOverrides }, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

function post(path, body, { headers = {}, ...envOverrides } = {}) {
	return call(
		path,
		{
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '::1', ...headers },
			body: typeof body === 'string' ? body : JSON.stringify(body),
		},
		envOverrides,
	);
}

beforeAll(async () => {
	await env.DB.batch([
		env.DB.prepare("INSERT INTO Categories (category_id, name) VALUES (1, 'WAF Managed Rules'), (2, 'Performance')"),
		env.DB.prepare(
			"INSERT INTO CloudflareFeatures (feature_id, name, feature_url) VALUES (1, 'WAF', 'https://developers.cloudflare.com/waf/')",
		),
		env.DB.prepare(
			`INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, source_reference)
			 VALUES ('Use rate_limit rules', 'Throttle abusive clients.', 'Security', 1, 1, 'Recommended', NULL, 'https://developers.cloudflare.com/'),
			        ('Enable HTTP/3', 'Faster connections.', 'Performance', 2, 1, 'Optional', 'Medium', 'https://developers.cloudflare.com/')`,
		),
	]);
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe('public read API', () => {
	it('lists practices with ids, cache and CORS headers', async () => {
		const response = await call('/api/practices');
		expect(response.status).toBe(200);
		expect(response.headers.get('Cache-Control')).toContain('max-age=60');
		expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
		expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
		expect(response.headers.get('X-Robots-Tag')).toContain('noindex');

		const body = await response.json();
		expect(body.success).toBe(true);
		expect(body.count).toBe(body.data.length);
		expect(body.data[0]).toHaveProperty('category_id');
		expect(body.data[0]).toHaveProperty('feature_id');
	});

	it('filters by enum and id parameters', async () => {
		const body = await (await call('/api/practices?area=Performance&categoryId=2')).json();
		expect(body.data.map((p) => p.title)).toEqual(['Enable HTTP/3']);
	});

	it('treats LIKE wildcards in search literally', async () => {
		const underscore = await (await call('/api/practices?search=rate_limit')).json();
		expect(underscore.data.map((p) => p.title)).toEqual(['Use rate_limit rules']);

		const percent = await (await call('/api/practices?search=%25')).json();
		expect(percent.count).toBe(0);
	});

	it('serves reads from the cached PublicReads entrypoint with edge TTL and purge tags', async () => {
		const practices = await call('/api/practices');
		expect(practices.headers.get('Cache-Tag')).toBe('practices');
		expect(practices.headers.get('Cloudflare-CDN-Cache-Control')).toContain('max-age=3600');
		expect((await call('/api/categories')).headers.get('Cache-Tag')).toBe('taxonomy');
	});

	it('returns categories and features', async () => {
		expect((await (await call('/api/categories')).json()).data).toContainEqual({ id: 1, name: 'WAF Managed Rules' });
		expect((await (await call('/api/features')).json()).data[0]).toMatchObject({ id: 1, name: 'WAF' });
	});

	it('answers CORS preflight and rejects other methods', async () => {
		expect((await call('/api/practices', { method: 'OPTIONS' })).status).toBe(204);

		const response = await call('/api/practices', { method: 'POST', body: '{}' });
		expect(response.status).toBe(405);
		expect(response.headers.get('Allow')).toBe('GET, OPTIONS');
	});

	it('returns JSON 404 for unknown API routes', async () => {
		const response = await call('/api/nope');
		expect(response.status).toBe(404);
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(await response.json()).toMatchObject({ success: false, error: 'API endpoint not found' });
	});
});

describe('write API authentication', () => {
	it('requires an Access JWT', async () => {
		const response = await post('/dashboard/api/practices', VALID_PRACTICE, { ALLOW_LOCAL_WRITES: 'false' });
		expect(response.status).toBe(401);
	});

	it('rejects a token that fails verification', async () => {
		vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ keys: [] }));
		const response = await post('/dashboard/api/practices', VALID_PRACTICE, {
			ALLOW_LOCAL_WRITES: 'false',
			headers: { 'Cf-Access-Jwt-Assertion': 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln' },
		});
		expect(response.status).toBe(403);
	});

	it('fails closed when Access is not configured', async () => {
		const response = await post('/dashboard/api/practices', VALID_PRACTICE, { ALLOW_LOCAL_WRITES: 'false', ACCESS_AUD: '' });
		expect(response.status).toBe(503);
	});

	it('only allows the local-dev bypass from a loopback client IP', async () => {
		const response = await post('/dashboard/api/practices', VALID_PRACTICE, {
			ALLOW_LOCAL_WRITES: 'true',
			headers: { 'CF-Connecting-IP': '203.0.113.7' },
		});
		expect(response.status).toBe(401);
	});
});

describe('write API validation (local-dev bypass)', () => {
	const local = { ALLOW_LOCAL_WRITES: 'true' };

	it('creates a practice, trims input, and the next read includes it', async () => {
		const response = await post('/dashboard/api/practices', VALID_PRACTICE, local);
		expect(response.status).toBe(201);
		const { id } = await response.json();

		const { data } = await (await call('/api/practices')).json();
		expect(data.some((p) => p.practice_id === id)).toBe(true);

		const row = await env.DB.prepare('SELECT title, category_id, difficulty_level FROM BestPractices WHERE practice_id = ?')
			.bind(id)
			.first();
		expect(row).toEqual({ title: 'Enable WAF', category_id: 1, difficulty_level: 'Easy' });
	});

	it('requires a JSON content type', async () => {
		const response = await post('/dashboard/api/practices', VALID_PRACTICE, { ...local, headers: { 'Content-Type': 'text/plain' } });
		expect(response.status).toBe(415);
	});

	it('rejects malformed and non-object bodies', async () => {
		expect((await post('/dashboard/api/practices', '{bad', local)).status).toBe(400);
		expect((await post('/dashboard/api/practices', [], local)).status).toBe(400);
	});

	it('reports every invalid field', async () => {
		const response = await post(
			'/dashboard/api/practices',
			{ ...VALID_PRACTICE, title: 5, domain: 'Nope', category_id: '1x', source_reference: 'javascript:alert(1)' },
			local,
		);
		expect(response.status).toBe(400);
		const { error } = await response.json();
		for (const field of ['title', 'domain', 'category_id', 'source_reference']) expect(error).toContain(field);
	});

	it('maps foreign key violations to 400', async () => {
		const response = await post('/dashboard/api/practices', { ...VALID_PRACTICE, category_id: 999 }, local);
		expect(response.status).toBe(400);
		expect((await response.json()).error).toBe('Unknown category_id or feature_id');
	});

	it('rejects oversized bodies', async () => {
		const response = await post('/dashboard/api/practices', { ...VALID_PRACTICE, notes: 'x'.repeat(70_000) }, local);
		expect(response.status).toBe(413);
	});

	it('only accepts POST', async () => {
		expect((await call('/dashboard/api/practices')).status).toBe(405);
	});
});

describe('schema', () => {
	it('rejects difficulty values outside the allowed set', async () => {
		await expect(
			env.DB.prepare(
				"INSERT INTO BestPractices (title, description, domain, difficulty_level) VALUES ('t', 'd', 'Security', 'High')",
			).run(),
		).rejects.toThrow(/CHECK constraint failed/);
	});
});
