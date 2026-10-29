import { env } from 'cloudflare:workers';
import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import { createPractice, handleCreatePractice } from '../src/practice-creation';
import { validatePractice } from '../src/practice-validation';
import { withWriteRetry } from '../src/d1-retry';
import { normalizeApiRequest } from '../src/read-api';

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
			headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '::1', 'Idempotency-Key': crypto.randomUUID(), ...headers },
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
		expect(response.headers.get('Allow')).toBe('GET, HEAD, OPTIONS');
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
		expect(await (await call(`/practices/${id}.md`)).text()).toContain('Enable WAF');
		expect(await (await call('/sitemap.xml')).text()).toContain(`/practices/${id}</loc>`);

		const row = await env.DB.prepare('SELECT title, category_id, difficulty_level FROM BestPractices WHERE practice_id = ?')
			.bind(id)
			.first();
		expect(row).toEqual({ title: 'Enable WAF', category_id: 1, difficulty_level: 'Easy' });
	});

	it('requires a JSON content type', async () => {
		const response = await post('/dashboard/api/practices', VALID_PRACTICE, { ...local, headers: { 'Content-Type': 'text/plain' } });
		expect(response.status).toBe(415);
	});

	it('keeps explicit expressions separate from guidance and searches expression-only content', async () => {
		const expression = '(http.host eq "expression-only.example.com")';
		const guidance = 'Action: Block. Set thresholds from observed traffic.';
		const created = await post(
			'/dashboard/api/practices',
			{
				...VALID_PRACTICE,
				expression,
				expressions_configuration_details: guidance,
			},
			local,
		);
		expect(created.status).toBe(201);
		const { id } = await created.json();
		const { data } = await (await call('/api/practices?search=expression-only.example.com')).json();
		expect(data).toContainEqual(expect.objectContaining({ practice_id: id, expression, expressions_configuration_details: guidance }));
		const markdown = await (await call(`/practices/${id}.md`)).text();
		expect(markdown).toContain(`## Example expression\n\n\`\`\`text\n${expression}`);
		expect(markdown).toContain(`## Configuration guidance\n\n\`\`\`text\n${guidance}`);
	});

	it('rejects oversized or non-string expressions', async () => {
		for (const expression of ['x'.repeat(5001), { expression: 'not a string' }]) {
			const response = await post('/dashboard/api/practices', { ...VALID_PRACTICE, expression }, local);
			expect(response.status).toBe(400);
			expect((await response.json()).error).toContain('expression');
		}
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

describe('durable practice creation', () => {
	const local = { ALLOW_LOCAL_WRITES: 'true' };
	const path = '/dashboard/api/practices';

	it('requires a well-formed key', async () => {
		for (const key of ['', 'short', 'a'.repeat(129), 'unsafe key with spaces']) {
			expect((await post(path, VALID_PRACTICE, { ...local, headers: { 'Idempotency-Key': key } })).status).toBe(400);
		}
	});

	it('replays normalized data with the original ID and no additional insert', async () => {
		const headers = { 'Idempotency-Key': crypto.randomUUID() };
		const data = { ...VALID_PRACTICE, title: 'Replay-safe creation' };
		const first = await post(path, data, { ...local, headers });
		const second = await post(path, { ...data, category_id: 1, title: ` ${data.title} ` }, { ...local, headers });
		expect(first.status).toBe(201);
		expect(second.status).toBe(201);
		expect(second.headers.get('Cache-Control')).toBe('no-store');
		expect(await second.json()).toEqual(await first.json());
		expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM BestPractices WHERE title = ?').bind(data.title).first('n')).toBe(1);
	});

	it('rejects different data for a completed key', async () => {
		const headers = { 'Idempotency-Key': crypto.randomUUID() };
		expect((await post(path, VALID_PRACTICE, { ...local, headers })).status).toBe(201);
		const conflict = await post(path, { ...VALID_PRACTICE, title: 'Conflicting retry' }, { ...local, headers });
		expect(conflict.status).toBe(409);
		expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM BestPractices WHERE title = 'Conflicting retry'").first('n')).toBe(0);
	});

	it('serializes concurrent retries and concurrent conflicting payloads', async () => {
		const headers = { 'Idempotency-Key': crypto.randomUUID() };
		const responses = await Promise.all(Array.from({ length: 5 }, () => post(path, VALID_PRACTICE, { ...local, headers })));
		expect(responses.every((response) => response.status === 201)).toBe(true);
		const bodies = await Promise.all(responses.map((response) => response.json()));
		expect(new Set(bodies.map((body) => body.id)).size).toBe(1);
		const conflictHeaders = { 'Idempotency-Key': crypto.randomUUID() };
		const conflicts = await Promise.all(
			['Concurrent A', 'Concurrent B'].map((title) => post(path, { ...VALID_PRACTICE, title }, { ...local, headers: conflictHeaders })),
		);
		expect(conflicts.map((response) => response.status).sort()).toEqual([201, 409]);
	});

	it('recovers when D1 commits but the result is lost', async () => {
		let lost = false;
		const db = {
			prepare: (sql) => env.DB.prepare(sql),
			batch: vi.fn(async (statements) => {
				const result = await env.DB.batch(statements);
				if (!lost) {
					lost = true;
					throw new Error('Network connection lost');
				}
				return result;
			}),
		};
		const practice = validatePractice({ ...VALID_PRACTICE, title: 'Lost commit response' });
		const id = await createPractice(db, practice, 'test-subject', crypto.randomUUID());
		expect(db.batch).toHaveBeenCalledTimes(2);
		expect(await env.DB.prepare('SELECT practice_id FROM BestPractices WHERE title = ?').bind(practice.title).all()).toMatchObject({
			results: [{ practice_id: id }],
		});
	});

	it('rolls back the practice if recording its receipt fails', async () => {
		const db = {
			prepare: (sql) => env.DB.prepare(sql),
			batch: (statements) =>
				env.DB.batch([
					statements[0],
					env.DB.prepare("INSERT INTO PracticeCreations (operation_key, payload_hash, practice_id) VALUES ('broken', 'hash', NULL)"),
				]),
		};
		const practice = validatePractice({ ...VALID_PRACTICE, title: 'Rolled back creation' });
		await expect(createPractice(db, practice, 'test-subject', crypto.randomUUID())).rejects.toThrow(/NOT NULL/);
		expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM BestPractices WHERE title = ?').bind(practice.title).first('n')).toBe(0);
	});

	it('recovers on a later client retry after all committed responses were lost', async () => {
		vi.spyOn(Math, 'random').mockReturnValue(0);
		const db = {
			prepare: (sql) => env.DB.prepare(sql),
			batch: vi.fn(async (statements) => {
				await env.DB.batch(statements);
				throw new Error('Network connection lost');
			}),
		};
		const key = crypto.randomUUID();
		const practice = validatePractice({ ...VALID_PRACTICE, title: 'Retry after exhausted commit responses' });
		await expect(createPractice(db, practice, 'test-subject', key)).rejects.toThrow('Network connection lost');
		expect(db.batch).toHaveBeenCalledTimes(4);
		const recovered = await createPractice(env.DB, practice, 'test-subject', key);
		expect(await env.DB.prepare('SELECT practice_id FROM BestPractices WHERE title = ?').bind(practice.title).all()).toMatchObject({
			results: [{ practice_id: recovered }],
		});
	});

	it('scopes keys to the authenticated subject and stores neither raw keys nor identities', async () => {
		const key = crypto.randomUUID();
		const practice = validatePractice(VALID_PRACTICE);
		const a = await createPractice(env.DB, practice, 'subject-a', key);
		const b = await createPractice(env.DB, practice, 'subject-b', key);
		expect(a).not.toBe(b);
		const receipts = await env.DB.prepare('SELECT operation_key FROM PracticeCreations WHERE practice_id IN (?, ?)').bind(a, b).all();
		expect(receipts.results).toHaveLength(2);
		for (const receipt of receipts.results) expect(receipt.operation_key).toMatch(/^[a-f0-9]{64}$/);
	});

	it('does not consume a key on validation/foreign-key failure', async () => {
		const headers = { 'Idempotency-Key': crypto.randomUUID() };
		expect((await post(path, { ...VALID_PRACTICE, category_id: 999 }, { ...local, headers })).status).toBe(400);
		expect((await post(path, VALID_PRACTICE, { ...local, headers })).status).toBe(201);
	});

	it('bounds transient retries and never retries permanent failures', async () => {
		const transient = vi.fn().mockRejectedValue(new Error('Network connection lost'));
		await expect(withWriteRetry(transient, { baseDelayMs: 0 })).rejects.toThrow('Network connection lost');
		expect(transient).toHaveBeenCalledTimes(4);
		const permanent = vi.fn().mockRejectedValue(new Error('FOREIGN KEY constraint failed'));
		await expect(withWriteRetry(permanent)).rejects.toThrow(/FOREIGN KEY/);
		expect(permanent).toHaveBeenCalledOnce();
	});

	it('keeps a committed write successful after purge failure and purges again on replay', async () => {
		vi.spyOn(console, 'error').mockImplementation(() => {});
		const purgePractices = vi.fn().mockRejectedValueOnce(new Error('Purge unavailable')).mockResolvedValue({ success: true });
		const ctx = { exports: { PublicReads: { purgePractices } } };
		const key = crypto.randomUUID();
		const create = () => {
			const request = new Request(`${ORIGIN}${path}`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Idempotency-Key': key, 'CF-Connecting-IP': '::1' },
				body: JSON.stringify(VALID_PRACTICE),
			});
			return handleCreatePractice(request, { ...env, ...local }, ctx, new URL(request.url));
		};
		const first = await create();
		const replay = await create();
		expect(first.status).toBe(201);
		expect(await replay.json()).toEqual(await first.json());
		expect(purgePractices).toHaveBeenCalledTimes(2);
	});
});

describe('API cache key normalization', () => {
	it('keeps only effective, canonical filters in a fixed order', () => {
		const request = new Request(
			`${ORIGIN}/api/practices?unused=x&impact=High&area=invalid&categoryId=01&categoryId=2&search=%20rate%00_limit%20`,
		);
		expect(normalizeApiRequest(request).url).toBe(`${ORIGIN}/api/practices?search=rate_limit&categoryId=1&impact=High`);
		expect(normalizeApiRequest(new Request(`${ORIGIN}/api/features?unused=1`)).url).toBe(`${ORIGIN}/api/features`);
		expect(normalizeApiRequest(new Request(`${ORIGIN}/api/practices?search=${'x'.repeat(300)}`)).url.split('search=')[1]).toHaveLength(200);
	});
});
