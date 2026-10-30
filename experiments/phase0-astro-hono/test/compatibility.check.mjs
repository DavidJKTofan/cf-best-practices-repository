import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFile, readdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { once } from 'node:events';
import wrangler from 'wrangler';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

const { createTestHarness, unstable_splitSqlQuery: splitSqlQuery } = wrangler;

// Exercise the BUILT Worker (including Hono, Astro, D1 and real ctx.exports), not an imported handler mock.
let server, jwksServer, privateKey, issuer, db;
const audience = 'phase0-test-audience';
const ID = 18;
const path = '/dashboard/api/practices';
const payload = {
	title: 'Phase 0 local creation',
	description: 'Synthetic compatibility fixture, not catalog guidance.',
	domain: 'General',
	category_id: 1,
	feature_id: 1,
	recommendation_level: 'Situational',
	impact_level: 'Low',
	source_reference: 'https://developers.cloudflare.com/workers/',
};

async function token({ aud = audience, exp = Math.floor(Date.now() / 1000) + 300 } = {}) {
	return new SignJWT({ email: 'writer@example.com' })
		.setProtectedHeader({ alg: 'RS256', kid: 'phase0-key' })
		.setIssuer(issuer)
		.setAudience(aud)
		.setSubject('phase0-writer')
		.setIssuedAt()
		.setExpirationTime(exp)
		.sign(privateKey);
}

async function post(body, key = crypto.randomUUID(), jwt = undefined, extraHeaders = {}) {
	return server.fetch(path, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Idempotency-Key': key,
			'Cf-Access-Jwt-Assertion': jwt ?? (await token()),
			...extraHeaders,
		},
		body,
		duplex: 'half',
	});
}

before(
	async () => {
		const pair = await generateKeyPair('RS256', { modulusLength: 2048 });
		privateKey = pair.privateKey;
		const jwk = { ...(await exportJWK(pair.publicKey)), kid: 'phase0-key', alg: 'RS256' };
		jwksServer = createServer((req, res) => {
			if (req.url !== '/cdn-cgi/access/certs') {
				res.writeHead(404).end();
				return;
			}
			res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ keys: [jwk] }));
		}).listen(0, '127.0.0.1');
		await once(jwksServer, 'listening');
		issuer = `http://127.0.0.1:${jwksServer.address().port}`;
		server = createTestHarness({
			workers: [
				{
					configPath: './dist/server/wrangler.json',
					vars: {
						ACCESS_TEAM_DOMAIN: issuer,
						ACCESS_AUD: audience,
					},
				},
			],
		});
		await server.listen();
		({ DB: db } = await server.getWorker().getEnv());
		const migrations = new URL('../../../migrations/', import.meta.url);
		for (const file of (await readdir(migrations)).filter((f) => f.endsWith('.sql')).sort()) {
			const statements = splitSqlQuery(await readFile(new URL(file, migrations), 'utf8'));
			await db.batch(statements.map((sql) => db.prepare(sql)));
		}
		const seed = await readFile(new URL('../../../initial_data.sql', import.meta.url), 'utf8');
		await db.batch(splitSqlQuery(seed).map((sql) => db.prepare(sql)));
	},
	{ timeout: 60_000 },
);

after(async () => {
	await server?.close();
	if (jwksServer) await new Promise((resolve, reject) => jwksServer.close((err) => (err ? reject(err) : resolve())));
});

test('Astro SSR is reached via the named PublicReads loopback and preserves header policy', async () => {
	const response = await server.fetch(`/practices/${ID}?utm_source=ignored`);
	assert.equal(response.status, 200);
	assert.equal(response.headers.get('X-Phase0-Renderer'), 'astro');
	assert.equal(response.headers.get('X-Phase0-Gateway'), 'hono');
	assert.equal(response.headers.get('Vary'), 'Accept');
	assert.equal(response.headers.get('Cache-Tag'), 'practices');
	assert.equal(response.headers.get('Cloudflare-CDN-Cache-Control'), 'public, max-age=3600, stale-while-revalidate=86400');
	assert.equal(response.headers.get('Set-Cookie'), null);
	assert.equal(response.headers.get('ETag'), null);
	assert.match(await response.text(), /Observe Methods Unexpected for a Specific Endpoint/);
});

test('HTML, negotiated Markdown, explicit Markdown and JSON contain the same existing record', async () => {
	const record = await db.prepare('SELECT * FROM BestPractices WHERE practice_id = ?').bind(ID).first();
	for (const [url, accept] of [
		[`/practices/${ID}`, 'text/html'],
		[`/practices/${ID}`, 'text/html;q=.2,text/markdown;q=1'],
		[`/practices/${ID}.md`, 'text/html'],
	]) {
		const response = await server.fetch(url, { headers: { Accept: accept } });
		const raw = await response.text();
		// Compare prose semantics, not the backslashes required for safe Markdown.
		const body = response.headers.get('Content-Type')?.includes('text/markdown') ? raw.replace(/\\([\\`*_{}\[\]<>()#+.!|~-])/g, '$1') : raw;
		assert.equal(response.status, 200);
		assert.ok(body.includes(record.title));
		assert.ok(body.includes(record.description));
		assert.ok(body.includes(record.source_reference));
		if (url.endsWith('.md') || accept.includes('q=')) assert.match(response.headers.get('Content-Type'), /text\/markdown/);
	}
	const apiResponse = await server.fetch('/api/practices?search=Observe%20Methods');
	const api = await apiResponse.json();
	assert.equal(apiResponse.status, 200, JSON.stringify({ api, logs: server.getLogs() }));
	assert.equal(api.data[0].practice_id, ID);
	assert.equal(api.data[0].expression, record.expression);
});

test('retains the D1 LIKE-limit proof while the shared v1 query accepts long literal searches', async () => {
	// The standalone production-query correction preserves the 200-character
	// normalizer but no longer uses LIKE. D1's underlying limit still applies.
	const query = 'x'.repeat(49); // '%' + 49 bytes + '%' exceeds the documented 50-byte limit.
	await assert.rejects(db.prepare("SELECT 'example' LIKE ?").bind(`%${query}%`).all(), /LIKE or GLOB pattern too complex/);
	const response = await server.fetch(`/api/practices?search=${query}`);
	assert.equal(response.status, 200);
	assert.equal(response.headers.get('Cache-Tag'), 'practices');
	assert.deepEqual(await response.json(), { success: true, data: [], count: 0 });
});

test('Markdown q=0 exclusion remains HTML and homepage is rendered without JS', async () => {
	const html = await server.fetch(`/practices/${ID}`, { headers: { Accept: 'text/markdown;q=0,*/*' } });
	assert.equal(html.headers.get('X-Phase0-Renderer'), 'astro');
	await html.body.cancel();
	const home = await server.fetch('/');
	assert.match(await home.text(), /href="\/practices\/1"/);
});

test('HEAD, preflight, 405 and missing-ID responses retain their boundaries', async () => {
	const head = await server.fetch(`/practices/${ID}`, { method: 'HEAD' });
	assert.equal(head.status, 200);
	assert.equal(await head.text(), '');
	const options = await server.fetch(`/practices/${ID}`, { method: 'OPTIONS' });
	assert.equal(options.status, 204);
	assert.match(options.headers.get('Access-Control-Allow-Methods'), /HEAD/);
	const unsupported = await server.fetch(`/practices/${ID}`, { method: 'POST' });
	assert.equal(unsupported.status, 405);
	const missing = await server.fetch('/practices/2147483647');
	assert.equal(missing.status, 404);
	assert.equal(missing.headers.get('Cache-Control'), 'no-store');
	assert.equal(missing.headers.get('X-Robots-Tag'), 'noindex');
});

test('static file and built CSS bypass the Worker; server modules/maps are not public', async () => {
	const staticResponse = await server.fetch('/probe.txt');
	assert.equal(await staticResponse.text(), 'phase0-static-asset\n');
	assert.equal(staticResponse.headers.get('X-Phase0-Renderer'), null);
	assert.equal(staticResponse.headers.get('X-Phase0-Gateway'), null);
	const home = await (await server.fetch('/')).text();
	const href = home.match(/href="([^"]+\.css)"/)?.[1];
	assert.ok(href, 'Astro must emit CSS as a file asset');
	const css = await server.fetch(href);
	assert.equal(css.status, 200);
	assert.equal(css.headers.get('X-Phase0-Renderer'), null);
	assert.equal(css.headers.get('X-Phase0-Gateway'), null);
	await css.body.cancel();
	for (const url of ['/worker.ts', '/worker.js.map', '/wrangler.json', '/src/access.ts']) {
		const response = await server.fetch(url);
		assert.equal(response.status, 404, url);
		await response.body.cancel();
	}
});

test('Access denies absent, wrong-audience, expired and tampered JWTs through Hono', async () => {
	const absent = await server.fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
	assert.equal(absent.status, 401);
	for (const jwt of [await token({ aud: 'wrong' }), await token({ exp: 1 }), `${await token()}tampered`]) {
		const response = await post(JSON.stringify(payload), crypto.randomUUID(), jwt);
		assert.equal(response.status, 403);
		assert.equal(response.headers.get('Cache-Control'), 'no-store');
	}
});

test('signed-JWT creation and unchanged replay preserve receipts and dispatch purge RPC each time', async () => {
	server.clearLogs();
	const key = crypto.randomUUID();
	const first = await post(JSON.stringify(payload), key);
	assert.equal(first.status, 201);
	assert.equal(first.headers.get('Cache-Control'), 'no-store');
	const created = await first.json();
	const retry = await post(JSON.stringify(payload), key);
	assert.equal(retry.status, 201);
	assert.equal((await retry.json()).id, created.id);
	const receipts = await db.prepare('SELECT count(*) AS count FROM PracticeCreations WHERE practice_id = ?').bind(created.id).first();
	assert.equal(receipts.count, 1);
	const changed = await post(JSON.stringify({ ...payload, title: 'Different' }), key);
	assert.equal(changed.status, 409);
	const logs = JSON.stringify(server.getLogs());
	assert.equal(logs.split('phase0 purge RPC').length - 1, 2);
	assert.ok(logs.includes('cacheEmulated'), 'RPC log explicitly distinguishes dispatch from real cache purging');
});

test('JSON media type, malformed JSON/UTF-8 and streamed byte bounds survive routing', async () => {
	assert.equal((await post('{}', undefined, undefined, { 'Content-Type': 'text/plain' })).status, 415);
	assert.equal((await post('{')).status, 400);
	assert.equal((await post(new Uint8Array([0xc3, 0x28]))).status, 400);
	const bytes = new TextEncoder().encode(JSON.stringify({ title: 'é'.repeat(40_000) }));
	const stream = new ReadableStream({
		start(controller) {
			controller.enqueue(bytes.slice(0, 32_000));
			controller.enqueue(bytes.slice(32_000));
			controller.close();
		},
	});
	assert.equal((await post(stream)).status, 413);
});

test('stored text is escaped by Astro and legacy Markdown keeps safe fences', async () => {
	const title = 'Unsafe <script>alert(1)</script>';
	await db
		.prepare('INSERT INTO BestPractices (practice_id, title, description, domain, expression, source_reference) VALUES (?, ?, ?, ?, ?, ?)')
		.bind(900001, title, 'Synthetic fixture', 'General', '```\n<script>no</script>', 'javascript:alert(1)')
		.run();
	const html = await (await server.fetch('/practices/900001')).text();
	assert.ok(!html.includes('<script>alert(1)</script>'));
	assert.ok(!html.includes('href="javascript:'));
	assert.match(html, /&lt;script&gt;/);
	const md = await (await server.fetch('/practices/900001.md')).text();
	assert.ok(md.includes('````text'));
	assert.ok(!md.includes('javascript:'));
});
