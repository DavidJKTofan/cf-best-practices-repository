import { env } from 'cloudflare:workers';
import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import worker, { PublicReads } from '../src/index';
import { sha256 } from '../src/modules/editorial/authorization';
import { mutateEditorial } from '../src/modules/editorial/mutations';
import { validateCommand } from '../src/modules/editorial/validation';
import { contentFixture } from './fixtures/catalog-content';
import { CONTENT_TYPES } from '../src/content/types';
import starters from '../data/phase5/starters.json';

const ORIGIN = 'https://catalog.example.com';
const ISSUER = 'https://editorial-test.cloudflareaccess.com';
const ACTIVE = { state: 'active', reason: null, supersededBy: null };
let privateKey, jwk;
const tokens = {},
	hashes = {};
const purge = vi.fn().mockResolvedValue({ success: true });
function envelope(type = 'recommendation', title = 'EDITORIAL_PRIVATE_CANARY') {
	return {
		content: {
			...contentFixture(type),
			title,
			evidence: 'public-docs',
			factVerifiedAt: '2026-10-30',
			modifiedAt: '2026-10-30',
			reviewDueAt: '2099-01-01',
		},
		lifecycle: ACTIVE,
	};
}
async function call(path, { actor = 'author', method = 'GET', body, key = crypto.randomUUID(), headers = {}, overrides = {} } = {}) {
	const ctx = createExecutionContext();
	Object.defineProperty(ctx, 'exports', {
		value: { PublicReads: { purgePractices: purge, fetch: (request) => new PublicReads({}, env).fetch(request) } },
	});
	const response = await worker.fetch(
		new Request(`${ORIGIN}${path}`, {
			method,
			headers: {
				...(tokens[actor] ? { 'Cf-Access-Jwt-Assertion': tokens[actor] } : {}),
				...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
				'Idempotency-Key': key,
				...headers,
			},
			body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
		}),
		{ ...env, ACCESS_TEAM_DOMAIN: ISSUER, ACCESS_AUD: 'editorial-aud', ...overrides },
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return response;
}
async function command(id, action, body, actor = 'author', extra = {}) {
	return call(`/dashboard/api/catalog${id ? `/${id}/${action}` : ''}`, {
		actor,
		method: action === 'draft' ? 'PUT' : 'POST',
		body,
		...extra,
	});
}
async function create(input = envelope()) {
	const response = await command(null, null, input);
	expect(response.status, await response.clone().text()).toBe(201);
	return (await response.json()).data.practiceId;
}
async function approve(id, version = 1) {
	expect((await command(id, 'submit', { expectedVersion: version })).status).toBe(200);
	expect((await command(id, 'review', { expectedVersion: version + 1, decision: 'approve' }, 'reviewer')).status).toBe(200);
}
async function publish(id, version = 3, extra = {}) {
	return command(id, 'publish', { expectedVersion: version }, 'publisher', extra);
}
beforeAll(async () => {
	const pair = await generateKeyPair('RS256', { modulusLength: 2048 });
	privateKey = pair.privateKey;
	jwk = { ...(await exportJWK(pair.publicKey)), kid: 'editorial-test', alg: 'RS256' };
	for (const actor of ['author', 'reviewer', 'publisher', 'ungranted', 'other']) {
		tokens[actor] = await new SignJWT({ email: `${actor}@example.com`, roles: ['publisher'] })
			.setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
			.setIssuer(ISSUER)
			.setAudience('editorial-aud')
			.setSubject(actor)
			.setExpirationTime('1h')
			.sign(privateKey);
		hashes[actor] = await sha256(JSON.stringify([ISSUER, 'user', actor]));
	}
	await env.DB.prepare(
		`INSERT INTO CatalogTaxa (kind, slug, label) VALUES
		('family', 'application-services', 'Application'), ('family', 'cloudflare-one', 'One'), ('family', 'developer-platform', 'Developer'),
		('product', 'waf', 'WAF'), ('product', 'workers', 'Workers'), ('product', 'd1', 'D1'), ('product', 'access', 'Access'), ('product', 'tunnel', 'Tunnel')`,
	).run();
	for (const [actor, roles] of [
		['author', ['editor', 'reviewer', 'publisher']],
		['reviewer', ['reviewer']],
		['publisher', ['publisher']],
		['other', ['editor']],
	])
		for (const role of roles) await env.DB.prepare('INSERT INTO EditorialRoles VALUES (?, ?)').bind(hashes[actor], role).run();
});
beforeEach(() => {
	purge.mockClear();
	vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ keys: [jwk] }));
});
afterEach(() => vi.restoreAllMocks());

describe('private editorial authorization and validation', () => {
	it('requires a verified Access identity AND explicit private role; signed role claims and headers do not grant roles', async () => {
		for (const actor of ['missing', 'ungranted']) {
			const response = await call('/dashboard/api/catalog', { actor, headers: { 'X-Editorial-Role': 'publisher' } });
			expect(response.status).toBe(actor === 'missing' ? 401 : 403);
			expect(response.headers.get('Cache-Control')).toContain('no-store');
		}
		expect((await command(null, null, envelope(), 'reviewer')).status).toBe(403);
		expect(
			(
				await call('/dashboard/api/catalog', {
					actor: 'missing',
					headers: { 'CF-Connecting-IP': '127.0.0.1' },
					overrides: { ALLOW_LOCAL_WRITES: 'true' },
				})
			).status,
		).toBe(403);
	});
	it('rejects cross-origin/form writes and preflights without CORS', async () => {
		for (const headers of [{ Origin: 'https://evil.example' }, { 'Sec-Fetch-Site': 'cross-site' }, { 'Content-Type': 'text/plain' }]) {
			const r = await command(null, null, envelope(), 'author', { headers });
			expect([403, 415]).toContain(r.status);
			expect(r.headers.has('Access-Control-Allow-Origin')).toBe(false);
		}
		expect((await call('/dashboard/api/catalog', { method: 'OPTIONS' })).status).toBe(405);
	});
	it('enforces actual bytes, UTF-8, exact fields, typed bodies and operation keys', async () => {
		for (const [body, headers, status] of [
			['x'.repeat(65537), { 'Content-Length': '1' }, 413],
			['{"bad":', {}, 400],
			[{ ...envelope(), privateNote: 'unexpected' }, {}, 400],
			[{ ...envelope(), content: { ...envelope().content, body: { html: '<script>' } } }, {}, 400],
			[envelope(), { 'Idempotency-Key': 'short' }, 400],
		])
			expect((await command(null, null, body, 'author', { headers })).status).toBe(status);
		const r = await worker.fetch(
			new Request(`${ORIGIN}/dashboard/api/catalog`, {
				method: 'POST',
				headers: { 'Cf-Access-Jwt-Assertion': tokens.author, 'Content-Type': 'application/json', 'Idempotency-Key': crypto.randomUUID() },
				body: new Uint8Array([0xff]),
			}),
			{ ...env, ACCESS_TEAM_DOMAIN: ISSUER, ACCESS_AUD: 'editorial-aud' },
			createExecutionContext(),
		);
		expect(r.status).toBe(400);
	});
	it.each(CONTENT_TYPES)('stores and safely previews %s without publication', async (type) => {
		const id = await create(envelope(type, '<script>PRIVATE_XSS</script>'));
		for (const suffix of ['preview', 'preview?format=markdown', 'draft']) {
			const response = await call(`/dashboard/api/catalog/${id}/${suffix}`);
			expect(response.status).toBe(200);
			expect(response.headers.get('Cache-Control')).toBe('private, no-store');
			expect(response.headers.get('X-Robots-Tag')).toContain('noindex');
			expect(response.headers.has('Cache-Tag')).toBe(false);
			if (suffix === 'preview') expect(await response.text()).not.toContain('<script>PRIVATE_XSS');
		}
		expect((await call(`/dashboard/api/catalog/${id}/preview`, { actor: 'missing' })).status).toBe(401);
		expect((await call(`/dashboard/api/catalog/${id}/preview`, { method: 'HEAD' })).headers.get('Cache-Control')).toContain('no-store');
		expect(purge).not.toHaveBeenCalled();
	});
});

describe('reviewed transactional publication', () => {
	it('reviews and publishes the runbook variant through the existing private role/version workflow', async () => {
		const content = structuredClone(starters[1].content);
		content.outcomes = [];
		content.reviewDueAt = '2099-01-01';
		const id = await create({ content, lifecycle: ACTIVE });
		const preview = await call(`/dashboard/api/catalog/${id}/preview?format=markdown`);
		expect(preview.headers.get('Cache-Control')).toBe('private, no-store');
		expect(await preview.text()).toContain('Read-only diagnosis');
		expect((await call(`/api/v2/entries/${id}`, { actor: 'missing' })).status).toBe(404);
		await approve(id);
		expect((await publish(id)).status).toBe(200);
		const { data } = await (await call(`/api/v2/entries/${id}`, { actor: 'missing' })).json();
		expect(data.body).toEqual(content.body);
		expect(data.v1Eligible).toBe(false);
		expect(purge).toHaveBeenCalledTimes(1);
	});
	it('replays saved-version transitions and scopes identical keys to separate actors', async () => {
		const key = crypto.randomUUID();
		const first = await (await command(null, null, envelope(), 'author', { key })).json();
		const other = await (await command(null, null, envelope(), 'other', { key })).json();
		expect(first.data.practiceId).not.toBe(other.data.practiceId);
		const id = first.data.practiceId;
		for (const [action, body, actor] of [
			['draft', { expectedVersion: 1, ...envelope() }, 'author'],
			['submit', { expectedVersion: 2 }, 'author'],
			['review', { expectedVersion: 3, decision: 'approve' }, 'reviewer'],
		]) {
			const operation = crypto.randomUUID();
			const response = await command(id, action, body, actor, { key: operation });
			expect(response.status).toBe(200);
			expect(await (await command(id, action, body, actor, { key: operation })).json()).toEqual(await response.json());
		}
		const competing = await Promise.all([publish(id, 4), publish(id, 4)]);
		expect(competing.map((r) => r.status).sort()).toEqual([200, 409]);
	});
	it('requires independent review, prevents authors publishing even with all roles, and preserves every old snapshot', async () => {
		const id = await create();
		expect((await publish(id, 1)).status).toBe(409);
		expect((await command(id, 'submit', { expectedVersion: 1 })).status).toBe(200);
		expect((await command(id, 'review', { expectedVersion: 2, decision: 'approve' })).status).toBe(409);
		expect((await command(id, 'review', { expectedVersion: 2, decision: 'approve' }, 'reviewer')).status).toBe(200);
		expect((await command(id, 'publish', { expectedVersion: 3 })).status).toBe(409);
		const published = await publish(id);
		expect(published.status, await published.clone().text()).toBe(200);
		const oldRevision = (await published.json()).data.revisionId;
		expect(purge).toHaveBeenCalledOnce();
		const changed = envelope('recommendation', 'NEXT_PRIVATE_REVISION');
		expect((await command(id, 'draft', { expectedVersion: 4, ...changed })).status).toBe(200);
		const before = await (await call(`/api/v2/entries/${id}`)).json();
		expect(before.data.title).toBe('EDITORIAL_PRIVATE_CANARY');
		await approve(id, 5);
		expect((await publish(id, 7)).status).toBe(200);
		expect((await (await call(`/api/v2/entries/${id}`)).json()).data.title).toBe('NEXT_PRIVATE_REVISION');
		expect(await env.DB.prepare('SELECT title FROM CatalogRevisions WHERE revision_id = ?').bind(oldRevision).first('title')).toBe(
			'EDITORIAL_PRIVATE_CANARY',
		);
		await expect(
			env.DB.prepare('UPDATE CatalogRevisions SET title = ? WHERE revision_id = ?').bind('tampered', oldRevision).run(),
		).rejects.toThrow('immutable');
	});
	it('makes all mutation replays stable, rejects changed payload/endpoint, and retries purge after lost publication response', async () => {
		const key = crypto.randomUUID();
		const first = await command(null, null, envelope(), 'author', { key });
		const value = await first.json();
		expect(await (await command(null, null, envelope(), 'author', { key })).json()).toEqual(value);
		expect((await command(null, null, envelope('recommendation', 'different'), 'author', { key })).status).toBe(409);
		const id = value.data.practiceId;
		await approve(id);
		const publicationKey = crypto.randomUUID();
		const original = await (await publish(id, 3, { key: publicationKey })).json();
		expect(await (await publish(id, 3, { key: publicationKey })).json()).toEqual(original);
		expect(purge).toHaveBeenCalledTimes(2);
		expect(await env.DB.prepare('SELECT COUNT(*) FROM CatalogPublications WHERE practice_id = ?').bind(id).first('COUNT(*)')).toBe(1);
	});
	it('handles simultaneous same-key creation and competing version writes', async () => {
		const key = crypto.randomUUID();
		const creations = await Promise.all([
			command(null, null, envelope(), 'author', { key }),
			command(null, null, envelope(), 'author', { key }),
		]);
		const [a, b] = await Promise.all(creations.map((r) => r.json()));
		expect(a).toEqual(b);
		const id = a.data.practiceId;
		const saves = await Promise.all([
			command(id, 'draft', { expectedVersion: 1, ...envelope('recommendation', 'A') }),
			command(id, 'draft', { expectedVersion: 1, ...envelope('recommendation', 'B') }),
		]);
		expect(saves.map((r) => r.status).sort()).toEqual([200, 409]);
	});
	it('recovers an internally retried lost commit without rerunning mutations', async () => {
		let calls = 0;
		const db = {
			withSession: (...args) => env.DB.withSession(...args),
			prepare: (...args) => env.DB.prepare(...args),
			batch: async (statements) => {
				const result = await env.DB.batch(statements);
				if (++calls === 1) throw new Error('Network connection lost');
				return result;
			},
		};
		const receipt = await mutateEditorial(db, 'create', null, validateCommand('create', envelope()), hashes.author, crypto.randomUUID());
		expect(calls).toBe(2);
		expect((await env.DB.prepare('SELECT version FROM CatalogDrafts WHERE practice_id = ?').bind(receipt.practiceId).first()).version).toBe(
			1,
		);
	});
	it('rolls back revision, receipt, version and pointer together when publication fails', async () => {
		const input = envelope();
		input.content.products = ['unknown-product'];
		const id = await create(input);
		await approve(id);
		const response = await publish(id);
		expect(response.status).toBe(400);
		expect(
			await env.DB.prepare('SELECT published_revision_id FROM CatalogEntries WHERE practice_id = ?')
				.bind(id)
				.first('published_revision_id'),
		).toBeNull();
		expect(await env.DB.prepare('SELECT COUNT(*) FROM CatalogRevisions WHERE practice_id = ?').bind(id).first('COUNT(*)')).toBe(0);
		expect(await env.DB.prepare('SELECT version FROM CatalogDrafts WHERE practice_id = ?').bind(id).first('version')).toBe(3);
		expect(
			await env.DB.prepare('SELECT COUNT(*) FROM EditorialMutations WHERE practice_id = ? AND purge = 1').bind(id).first('COUNT(*)'),
		).toBe(0);
		expect(purge).not.toHaveBeenCalled();
	});
	it('invalidates review after editing; request-changes returns to drafting; stale public base conflicts', async () => {
		const id = await create();
		await approve(id);
		expect((await command(id, 'draft', { expectedVersion: 3, ...envelope() })).status).toBe(200);
		expect((await publish(id, 4)).status).toBe(409);
		expect((await command(id, 'submit', { expectedVersion: 4 })).status).toBe(200);
		expect((await command(id, 'review', { expectedVersion: 5, decision: 'request-changes' }, 'reviewer')).status).toBe(200);
		await approve(id, 6);
		await env.DB.prepare('UPDATE EditorialDraftState SET base_revision_id = 999 WHERE practice_id = ?').bind(id).run();
		expect((await publish(id, 8)).status).toBe(409);
		expect((await command(id, 'rebase', { expectedVersion: 8, expectedPublishedRevisionId: 123 })).status).toBe(409);
		expect((await command(id, 'rebase', { expectedVersion: 8, expectedPublishedRevisionId: null })).status).toBe(200);
		await approve(id, 9);
		expect((await publish(id, 11)).status).toBe(200);
		await env.DB.prepare('UPDATE CatalogEntries SET published_revision_id = NULL WHERE practice_id = ?').bind(id).run();
		expect((await command(id, 'draft', { expectedVersion: 12, ...envelope() })).status).toBe(409);
		expect((await command(id, 'rebase', { expectedVersion: 12, expectedPublishedRevisionId: null })).status).toBe(200);
	});
	it('revoked grants fail closed, including an approved reviewer revoked before publication', async () => {
		const id = await create();
		await approve(id);
		await env.DB.prepare("DELETE FROM EditorialRoles WHERE actor_hash = ? AND role = 'reviewer'").bind(hashes.reviewer).run();
		expect((await publish(id)).status).toBe(409);
		await env.DB.prepare("INSERT INTO EditorialRoles VALUES (?, 'reviewer')").bind(hashes.reviewer).run();
	});
	it('blocks legacy conversion and incomplete/future/overdue fact verification', async () => {
		await env.DB.prepare("INSERT INTO BestPractices (title, description, domain) VALUES ('Legacy', 'Legacy', 'General')").run();
		const id = await env.DB.prepare('SELECT practice_id FROM BestPractices LIMIT 1').first('practice_id');
		expect((await command(id, 'draft', { expectedVersion: 0, ...envelope() })).status).toBe(409);
		for (const patch of [
			{ evidence: 'unreviewed', factVerifiedAt: null },
			{ factVerifiedAt: '2099-01-01' },
			{ reviewDueAt: '2020-01-01' },
		]) {
			const input = envelope();
			Object.assign(input.content, patch);
			const draft = await create(input);
			expect((await command(draft, 'submit', { expectedVersion: 1 })).status).toBe(400);
		}
	});
	it('publishes explicit deprecation/supersession, rejects self/private replacements, retains canonical reads', async () => {
		const replacement = await create(envelope('recommendation', 'Replacement'));
		await approve(replacement);
		await publish(replacement);
		const input = envelope();
		input.lifecycle = { state: 'superseded', reason: 'Use the reviewed replacement.', supersededBy: replacement };
		const id = await create(input);
		await approve(id);
		expect((await publish(id)).status).toBe(200);
		const detail = await (await call(`/api/v2/entries/${id}`)).json();
		expect(detail.data.lifecycle).toEqual(input.lifecycle);
		expect(await (await call(`/practices/${id}.md`)).text()).toContain(
			`Replacement: https://db.automatic-demo.com/practices/${replacement}`,
		);
		const hidden = await create();
		const bad = envelope();
		bad.lifecycle = { state: 'superseded', reason: 'Invalid target', supersededBy: hidden };
		const badId = await create(bad);
		await approve(badId);
		expect((await publish(badId)).status).toBe(409);
	});
	it('excludes drafts and query-flag previews from every public representation', async () => {
		const id = await create(envelope('recommendation', 'ONLY_UNPUBLISHED_EDITORIAL_CANARY'));
		for (const path of [
			'/api/v2/entries?q=ONLY_UNPUBLISHED',
			'/api/v2/facets',
			'/api/practices',
			'/index.md',
			'/catalog.md',
			'/llms-full.txt',
			'/sitemap.xml',
			'/llms.txt',
			`/api/v2/entries/${id}?draft=true`,
			`/practices/${id}.md?preview=true`,
		]) {
			const response = await call(path);
			expect(response.status, path).toBe(path.includes(`/${id}`) ? 404 : 200);
			expect(await response.text(), path).not.toContain('ONLY_UNPUBLISHED_EDITORIAL_CANARY');
		}
	});
});
