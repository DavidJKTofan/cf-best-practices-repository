import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, writeFile, symlink, realpath, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { validateStaging, productionConfig, stagingSource, checkGenerated, ROOT, SOURCE_KEYS } from '../release/staging.mjs';
import { runSmoke } from '../release/smoke.mjs';
import { filterFixture } from './helpers/release-filter-fixture.mjs';

const production = productionConfig();
function staging() {
	const config = structuredClone(production);
	config.name += '-staging';
	config.routes = [{ pattern: 'staging.example.com', custom_domain: true }];
	config.d1_databases = [
		{
			binding: 'DB',
			database_id: '00000000-0000-4000-8000-000000000001',
			database_name: 'fixture-staging',
			migrations_dir: resolve(ROOT, 'migrations'),
		},
	];
	config.vars = { ACCESS_TEAM_DOMAIN: 'https://fixture.cloudflareaccess.com', ACCESS_AUD: 'a'.repeat(64) };
	config.ratelimits[0].namespace_id = '999999';
	config.main = resolve(ROOT, 'src/astro-worker.ts');
	config.assets.directory = resolve(ROOT, 'public');
	return config;
}

test('isolated staging is explicit, preserves scoped assets/cache, and never proves live Access', () => {
	assert.deepEqual(validateStaging(staging(), production), {
		scope: 'offline-config-only',
		accessPolicyVerified: false,
		remoteEffects: 'none',
	});
});

test('staging rejects production targets, missing/automatic resources and security/cache drift', () => {
	for (const mutate of [
		(c) => (c.name = production.name),
		(c) => (c.routes = production.routes),
		(c) => (c.routes[0].pattern = production.routes[0].pattern.toUpperCase()),
		(c) => (c.routes[0].pattern = '*.example.com/*'),
		(c) => (c.d1_databases[0].database_id = production.d1_databases[0].database_id),
		(c) => (c.d1_databases[0].database_id = production.d1_databases[0].database_id.toUpperCase()),
		(c) => delete c.d1_databases[0].database_id,
		(c) => (c.d1_databases[0].database_id = '00000000-0000-0000-0000-000000000000'),
		(c) => (c.d1_databases[0].remote = true),
		(c) => (c.d1_databases[0].preview_database_id = production.d1_databases[0].database_id),
		(c) => (c.vars.ACCESS_AUD = production.vars.ACCESS_AUD),
		(c) => (c.vars.ALLOW_LOCAL_WRITES = 'true'),
		(c) => (c.vars.ACCESS_TEAM_DOMAIN = 'https://fixture.cloudflareaccess.com@evil.example'),
		(c) => (c.workers_dev = true),
		(c) => (c.preview_urls = true),
		(c) => (c.exports.default.cache.enabled = true),
		(c) => (c.cache = { enabled: true }),
		(c) => (c.assets.run_worker_first = true),
		(c) => c.assets.run_worker_first.pop(),
		(c) => (c.ratelimits[0].namespace_id = production.ratelimits[0].namespace_id),
		(c) => (c.ratelimits[0].namespace_id = '0' + production.ratelimits[0].namespace_id),
		(c) => (c.kv_namespaces = [{ binding: 'SESSION' }]),
		(c) => (c.services = [{ binding: 'OTHER', service: production.name }]),
		(c) => (c.env = { production: {} }),
	]) {
		const config = staging();
		mutate(config);
		assert.throws(() => validateStaging(config, production));
	}
});

test('opt-in staging source must be private, complete and use absolute real app paths', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'phase6-staging-config-'));
	const source = join(directory, 'wrangler.json');
	const config = Object.fromEntries(Object.entries(staging()).filter(([key]) => SOURCE_KEYS.has(key)));
	await writeFile(source, JSON.stringify(config), { mode: 0o600 });
	assert.equal(await stagingSource(source), await realpath(source));
	assert.ok((await readFile(source, 'utf8')).includes('fixture-staging'));
	await assert.rejects(stagingSource('wrangler.jsonc'));
	await assert.rejects(stagingSource(resolve(ROOT, 'wrangler.jsonc')));
	const alias = join(directory, 'in-repo.json');
	await symlink(resolve(ROOT, 'wrangler.jsonc'), alias);
	await assert.rejects(stagingSource(alias));
	config.main = './src/astro-worker.ts';
	await writeFile(source, JSON.stringify(config));
	await assert.rejects(stagingSource(source));
	config.main = resolve(ROOT, 'src/astro-worker.ts');
	config.build = { command: 'unreviewed-hook' };
	await writeFile(source, JSON.stringify(config));
	await assert.rejects(stagingSource(source));
});

test('generated staging check requires built paths and refuses public server maps/config', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'phase6-staging-artifacts-'));
	await mkdir(join(directory, 'server'));
	await mkdir(join(directory, 'client'));
	const source = join(directory, 'server/wrangler.json');
	const config = staging();
	config.main = 'entry.mjs';
	config.assets.directory = '../client';
	await writeFile(source, JSON.stringify(config));
	await writeFile(join(directory, 'server/entry.mjs'), 'export default {}');
	await writeFile(join(directory, 'client/style.css'), 'body { color: black }');
	assert.equal((await checkGenerated(source)).remoteEffects, 'none');
	await writeFile(join(directory, 'client/server.map'), '{}');
	await assert.rejects(checkGenerated(source));
	await assert.rejects(checkGenerated(resolve(ROOT, 'wrangler.jsonc')));
});

const BASE = 'https://catalog.example.com';
const skillBody = '# Read practices\n';
function fixtureFetch(log, { badRevision = false, redirectPublic = false, cacheHit = true, dashboardPublic = false, cookies = [] } = {}) {
	return async (target, init) => {
		const url = new URL(target);
		log.push({ target, init });
		assert.equal(url.origin, BASE);
		assert.ok(['GET', 'HEAD', 'OPTIONS'].includes(init.method));
		assert.equal(init.redirect, 'manual');
		assert.equal(init.credentials, 'omit');
		assert.deepEqual(Object.keys(init.headers), ['Accept']);
		assert.equal(init.body, undefined);
		assert.ok(init.signal);
		const path = url.pathname;
		if (path.startsWith('/dashboard'))
			return new Response(dashboardPublic ? 'PUBLIC_SHELL' : null, {
				status: dashboardPublic ? 200 : 302,
				headers: dashboardPublic ? {} : { Location: 'https://fixture.cloudflareaccess.com/cdn-cgi/access/login' },
			});
		if (redirectPublic) return new Response(null, { status: 302, headers: { Location: 'https://private-redirect.example/' } });
		if (init.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*' } });
		let type = 'text/html',
			body = '';
		const canonicalPath = path.replace(/\.md$/, '');
		const headers = { 'Cache-Control': 'public, max-age=60', 'Cf-Cache-Status': cacheHit ? 'HIT' : 'MISS' };
		if (path === '/api/practices') {
			type = 'application/json';
			body = JSON.stringify({ data: [{ practice_id: 18 }] });
		} else if (path.startsWith('/api/v2/entries/')) {
			type = 'application/json';
			body = JSON.stringify({
				data: path.endsWith('/18')
					? { schemaVersion: 0 }
					: { practiceId: 121, revisionId: badRevision ? 1 : 2, schemaVersion: 1, title: 'Published fixture', legacyClassification: null },
			});
		} else if (path === '/api/v2/entries') {
			type = 'application/json';
			body = JSON.stringify({ data: [{ practiceId: 18 }] });
		} else if (path === '/sitemap.xml') {
			type = 'application/xml';
			body = `<urlset><url><loc>${BASE}/practices/18</loc></url><url><loc>${BASE}/practices/121</loc></url></urlset>`;
		} else if (path === '/llms.txt') {
			type = 'text/plain';
			body = `${BASE}/practices/18`;
		} else if (path.endsWith('/index.json')) {
			type = 'application/json';
			body = JSON.stringify({
				skills: [
					{
						name: 'read-practices',
						url: `${BASE}/.well-known/agent-skills/read-practices/SKILL.md`,
						digest: `sha256:${createHash('sha256').update(skillBody).digest('hex')}`,
					},
				],
			});
		} else if (path.endsWith('/SKILL.md')) {
			type = 'text/markdown';
			body = skillBody;
		} else {
			const md =
				path.endsWith('.md') || (init.headers.Accept.includes('text/markdown') && !init.headers.Accept.includes('text/markdown;q=0'));
			type = md ? 'text/markdown' : 'text/html';
			body = md
				? `# Published fixture\n\nCanonical URL: ${BASE}${canonicalPath}\nRevision: 2\n`
				: `<html><head><link rel="canonical" href="${BASE}${path}"></head><body><h1>Published fixture</h1>Revision 2</body></html>`;
			headers.Vary = 'Accept';
			headers.Link = `<${BASE}${canonicalPath}>; rel="canonical"`;
		}
		if (type === 'application/json') headers['X-Robots-Tag'] = 'noindex';
		headers['Content-Type'] = type;
		const response = new Response(init.method === 'HEAD' ? null : body, { headers });
		for (const cookie of cookies) response.headers.append('Set-Cookie', cookie);
		return response;
	};
}

test('read-only smoke verifies variants, expected revision, discovery, anonymous denial and optional HITs', async () => {
	const log = [];
	const result = await runSmoke({ base: BASE, nativeId: 121, expectedRevision: 2, expectCacheHits: true, fetcher: fixtureFetch(log) });
	assert.equal(result.ok, true, JSON.stringify(result));
	assert.equal(result.remoteWrites, 'none');
	assert.equal(result.responseCookiePolicy, 'none');
	assert.ok(log.length > 20);
	assert.ok(!JSON.stringify(result).includes('Published fixture'));
});

test('legacy-filter opt-in verifies six SSR controls, v1/summary/detail/facet parity, normalization, Markdown and clear links', async () => {
	const log = [];
	const result = await runSmoke({
		base: BASE,
		nativeId: 121,
		expectedRevision: 2,
		expectLegacyFilters: true,
		fetcher: filterFixture(fixtureFetch(log)),
	});
	assert.equal(result.ok, true, JSON.stringify(result));
	assert.equal(result.legacyFiltersRequired, true);
	assert.deepEqual(
		result.checks.find((c) => c.name === 'recorded-legacy-filter-contract'),
		{ name: 'recorded-legacy-filter-contract', ok: true },
	);
	assert.ok(log.some(({ target }) => target.includes('categoryId=0001')));
	assert.ok(log.some(({ target }) => target.includes('categoryId=invalid&categoryId=1')));
	assert.ok(log.every(({ init }) => ['GET', 'HEAD', 'OPTIONS'].includes(init.method) && !init.body));
	const old = await runSmoke({ base: BASE, expectLegacyFilters: true, fetcher: fixtureFetch([]) });
	assert.equal(
		old.checks.find((c) => c.name === 'recorded-legacy-filter-contract').ok,
		false,
		'Old deployments must fail the feature expectation',
	);
});

test('legacy-filter expectation rejects native classification without widening public write access', async () => {
	const fixture = filterFixture(fixtureFetch([]));
	const result = await runSmoke({
		base: BASE,
		nativeId: 121,
		expectedRevision: 2,
		expectLegacyFilters: true,
		fetcher: async (target, init) => {
			const response = await fixture(target, init);
			if (new URL(target).pathname !== '/api/v2/entries/121') return response;
			const body = await response.json();
			body.data.legacyClassification = { domain: 'Security' };
			return Response.json(body, { headers: response.headers });
		},
	});
	assert.equal(result.ok, false);
	assert.equal(result.checks.find((c) => c.name === 'expected-native-revision-html-markdown-json').ok, false);
});

test('legacy-filter opt-in fails missing controls/classification, wrong counts, ignored filters, normalization and representation regressions', async () => {
	const mutations = [
		(url, body) => (url.pathname === '/catalog' ? body.replace('<select name="domain">', '<select name="wrong">') : body),
		(url, body) => (url.pathname === '/api/v2/entries/18' ? body.replace('"legacyClassification":', '"wrong":') : body),
		(url, body) => (url.pathname === '/api/v2/facets' ? body.replace(/"count":\d+/g, '"count":999') : body),
		(url, body) =>
			url.pathname === '/api/v2/entries' && url.searchParams.has('difficulty') ? JSON.stringify({ ...JSON.parse(body), total: 999 }) : body,
		(url, body) =>
			url.search.includes('categoryId=000') && url.pathname === '/api/v2/entries'
				? body.replace('"categoryId":"1"', '"categoryId":"0001"')
				: body,
		(url, body) =>
			url.search.includes('categoryId=invalid') && url.pathname === '/api/v2/entries'
				? JSON.stringify({ ...JSON.parse(body), total: 999 })
				: body,
		(url, body) => (url.pathname === '/catalog' && !body.startsWith('<html>') ? body.replace(/Difficulty:/g, 'Wrong:') : body),
		(url, body) => (url.pathname === '/catalog.md' ? body + '\nMismatched alias' : body),
		(url, body) =>
			url.pathname === '/catalog' && url.searchParams.get('page') === '2' ? body.replaceAll('name="categoryId"', 'name="wrong"') : body,
		(url, body) =>
			url.pathname === '/catalog' && url.searchParams.get('page') === '2'
				? body.replaceAll('href="/catalog?', 'href="/catalog?page=2&amp;')
				: body,
	];
	for (const mutate of mutations) {
		const fixture = filterFixture(fixtureFetch([]));
		const result = await runSmoke({
			base: BASE,
			expectLegacyFilters: true,
			fetcher: async (target, init) => {
				const response = await fixture(target, init);
				if (init.method !== 'GET') return response;
				return new Response(mutate(new URL(target), await response.text()), { status: response.status, headers: response.headers });
			},
		});
		assert.equal(result.checks.find((c) => c.name === 'recorded-legacy-filter-contract').ok, false, `Missed mutation: ${mutate}`);
		assert.equal(result.ok, false);
		assert.ok(!JSON.stringify(result).includes('Fixture & policy'), 'Diagnostics must not print response bodies');
	}
});

test('smoke rejects bot cookies by default and accepts only an explicit named edge-cookie opt-in', async () => {
	const cookies = ['__cf_bm=PRIVATE_COOKIE_VALUE; HttpOnly; Secure; SameSite=None; Expires=Wed, 21 Oct 2026 07:28:00 GMT'];
	const strict = await runSmoke({ base: BASE, fetcher: fixtureFetch([], { cookies }) });
	assert.equal(strict.ok, false);
	assert.equal(strict.responseCookiePolicy, 'none');
	const log = [];
	const allowed = await runSmoke({
		base: BASE,
		expectCacheHits: true,
		allowCloudflareBmCookie: true,
		fetcher: fixtureFetch(log, { cookies }),
	});
	assert.equal(allowed.ok, true, JSON.stringify(allowed));
	assert.equal(allowed.responseCookiePolicy, '__cf_bm-only');
	assert.ok(!JSON.stringify([strict, allowed, log]).includes('PRIVATE_COOKIE_VALUE'));
});

test('edge-cookie opt-in still rejects application, lookalike, mixed and folded cookies', async () => {
	for (const cookies of [
		['session=PRIVATE_COOKIE_VALUE'],
		['__cf_bm_extra=PRIVATE_COOKIE_VALUE'],
		['__CF_BM=PRIVATE_COOKIE_VALUE'],
		['__cf_bm=bot', 'session=PRIVATE_COOKIE_VALUE'],
		['__cf_bm=bot, session=PRIVATE_COOKIE_VALUE; Secure'],
		['__cf_bm=bot; Expires=Wed, 21 Oct 2026 07:28:00 GMT, session=PRIVATE_COOKIE_VALUE'],
	]) {
		const result = await runSmoke({ base: BASE, allowCloudflareBmCookie: true, fetcher: fixtureFetch([], { cookies }) });
		assert.equal(result.ok, false);
		assert.ok(!JSON.stringify(result).includes('PRIVATE_COOKIE_VALUE'));
	}
});

test('smoke detects stale revisions, unprotected dashboard and missing cache effects without following redirects', async () => {
	for (const option of [{ badRevision: true }, { dashboardPublic: true }, { cacheHit: false }, { redirectPublic: true }]) {
		const log = [];
		const result = await runSmoke({
			base: BASE,
			nativeId: 121,
			expectedRevision: 2,
			expectCacheHits: true,
			fetcher: fixtureFetch(log, option),
		});
		assert.equal(result.ok, false, JSON.stringify(option));
		assert.ok(!JSON.stringify(result).includes('PUBLIC_SHELL'));
		assert.ok(log.every((r) => new URL(r.target).origin === BASE));
	}
});

test('smoke rejects implicit/unsafe targets and stops oversized responses without silent success', async () => {
	for (const base of ['http://example.com', 'https://user:pass@example.com', 'https://example.com/path', undefined]) {
		await assert.rejects(runSmoke({ base }));
	}
	await assert.rejects(runSmoke({ base: BASE, nativeId: 121 }));
	await assert.rejects(runSmoke({ base: BASE, expectedRevision: 2 }));
	await assert.rejects(runSmoke({ base: BASE, legacyId: '18/../../private' }));
	let cancelled = 0;
	const result = await runSmoke({
		base: BASE,
		maxBytes: 8,
		fetcher: async () =>
			new Response(
				new ReadableStream({
					start(controller) {
						controller.enqueue(new Uint8Array(9));
					},
					cancel() {
						cancelled++;
					},
				}),
			),
	});
	assert.equal(result.ok, false);
	assert.ok(cancelled > 0);
});
