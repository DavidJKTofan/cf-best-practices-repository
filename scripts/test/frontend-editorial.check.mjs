import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { frontendHarness, seedFrontend, pilots } from './helpers/frontend-harness.mjs';

let server, jwks, db;
const tokens = {};
const base = '/dashboard/api/catalog';
const lifecycle = { state: 'active', reason: null, supersededBy: null };
const input = { content: { ...pilots[0], title: 'EDITORIAL_BUILT_PRIVATE_CANARY', reviewDueAt: '2099-01-01' }, lifecycle };
async function call(path, actor, method = 'GET', body, key = crypto.randomUUID()) {
	return server.fetch(path, {
		method,
		headers: { ...(actor ? { 'Cf-Access-Jwt-Assertion': tokens[actor] } : {}), 'Content-Type': 'application/json', 'Idempotency-Key': key },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}
before(
	async () => {
		const pair = await generateKeyPair('RS256', { modulusLength: 2048 });
		const jwk = { ...(await exportJWK(pair.publicKey)), kid: 'editorial-built-key', alg: 'RS256' };
		jwks = createServer((req, res) => {
			res
				.writeHead(req.url === '/cdn-cgi/access/certs' ? 200 : 404, { 'Content-Type': 'application/json' })
				.end(JSON.stringify({ keys: [jwk] }));
		}).listen(0, '127.0.0.1');
		await once(jwks, 'listening');
		const issuer = `http://127.0.0.1:${jwks.address().port}`;
		server = frontendHarness({ ACCESS_TEAM_DOMAIN: issuer, ACCESS_AUD: 'editorial-built-aud' });
		await server.listen();
		({ DB: db } = await server.getWorker().getEnv());
		await seedFrontend(db);
		for (const [actor, role] of [
			['author', 'editor'],
			['reviewer', 'reviewer'],
			['publisher', 'publisher'],
			['ungranted', null],
		]) {
			tokens[actor] = await new SignJWT({})
				.setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
				.setIssuer(issuer)
				.setAudience('editorial-built-aud')
				.setSubject(actor)
				.setExpirationTime('1h')
				.sign(pair.privateKey);
			if (role)
				await db
					.prepare('INSERT INTO EditorialRoles VALUES (?, ?)')
					.bind(
						createHash('sha256')
							.update(JSON.stringify([issuer, 'user', actor]))
							.digest('hex'),
						role,
					)
					.run();
		}
	},
	{ timeout: 60_000 },
);
after(async () => {
	await server?.close();
	if (jwks) await new Promise((resolve, reject) => jwks.close((err) => (err ? reject(err) : resolve())));
});

test('built gateway protects editorial APIs and serves an inert, noindex workbench without private content', async () => {
	for (const [actor, status] of [
		[undefined, 401],
		['ungranted', 403],
	]) {
		const response = await call(base, actor);
		assert.equal(response.status, status);
		assert.match(response.headers.get('Cache-Control'), /no-store/);
	}
	const page = await server.fetch('/dashboard/editorial');
	assert.equal(page.status, 200);
	assert.match(page.headers.get('X-Robots-Tag'), /noindex/);
	assert.match(page.headers.get('Cache-Control'), /no-store/);
	const html = await page.text();
	assert.match(html, /Typed content envelope/);
	assert.ok(!html.includes('PRIVATE_DRAFT_CANARY'));
	assert.equal((await server.fetch('/editorial.js')).status, 200);
});

test('built signed-identity journey keeps drafts private until atomic reviewed publication, then preserves revision parity', async () => {
	const created = await call(base, 'author', 'POST', input);
	assert.equal(created.status, 201, await created.clone().text());
	const id = (await created.json()).data.practiceId;
	for (const path of [
		'/',
		'/catalog',
		'/families/application-services',
		'/api/v2/entries',
		'/api/v2/facets',
		'/api/practices',
		'/index.md',
		'/llms-full.txt',
		'/sitemap.xml',
		'/llms.txt',
	]) {
		const response = await server.fetch(path);
		assert.equal(response.status, 200, path);
		assert.ok(!(await response.text()).includes(input.content.title), path);
	}
	assert.equal((await server.fetch(`/practices/${id}?preview=true`)).status, 404);
	const preview = await call(`${base}/${id}/preview`, 'reviewer');
	assert.equal(preview.status, 200);
	assert.match(preview.headers.get('Cache-Control'), /private, no-store/);
	assert.equal(preview.headers.get('Cache-Tag'), null);
	assert.ok((await preview.text()).includes(input.content.title));
	assert.equal((await call(`${base}/${id}/submit`, 'author', 'POST', { expectedVersion: 1 })).status, 200);
	assert.equal((await call(`${base}/${id}/review`, 'reviewer', 'POST', { expectedVersion: 2, decision: 'approve' })).status, 200);
	const key = crypto.randomUUID();
	const published = await call(`${base}/${id}/publish`, 'publisher', 'POST', { expectedVersion: 3 }, key);
	assert.equal(published.status, 200, await published.clone().text());
	const receipt = await published.json();
	assert.deepEqual(await (await call(`${base}/${id}/publish`, 'publisher', 'POST', { expectedVersion: 3 }, key)).json(), receipt);
	for (const path of [`/practices/${id}`, `/practices/${id}.md`, `/api/v2/entries/${id}`]) {
		const response = await server.fetch(path);
		assert.equal(response.status, 200);
		const text = await response.text();
		assert.ok(text.replaceAll('\\_', '_').includes(input.content.title));
		assert.ok(text.includes(String(receipt.data.revisionId)));
	}
	const deprecated = { ...input, lifecycle: { state: 'deprecated', reason: 'Reviewed retirement fixture.', supersededBy: null } };
	assert.equal((await call(`${base}/${id}/draft`, 'author', 'PUT', { expectedVersion: 4, ...deprecated })).status, 200);
	assert.ok(!(await (await server.fetch(`/practices/${id}`)).text()).includes('Reviewed retirement fixture.'));
	assert.equal((await call(`${base}/${id}/submit`, 'author', 'POST', { expectedVersion: 5 })).status, 200);
	assert.equal((await call(`${base}/${id}/review`, 'reviewer', 'POST', { expectedVersion: 6, decision: 'approve' })).status, 200);
	assert.equal((await call(`${base}/${id}/publish`, 'publisher', 'POST', { expectedVersion: 7 })).status, 200);
	assert.match(await (await server.fetch(`/practices/${id}`)).text(), /Deprecated guidance/);
	assert.match(await (await server.fetch(`/practices/${id}.md`)).text(), /Reviewed retirement fixture/);
	assert.equal((await (await server.fetch(`/api/v2/entries/${id}`)).json()).data.lifecycle.state, 'deprecated');
	const history = await (await call(`${base}/${id}/history`, 'reviewer')).json();
	assert.equal(history.data.length, 2);
});
