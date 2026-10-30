// Anonymous GET/HEAD/OPTIONS only. No writes, credentials, redirects, or purge API.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parse } from 'parse5';

function origin(value) {
	const url = new URL(value);
	assert.equal(url.protocol, 'https:', 'Explicit HTTPS origin required');
	assert.ok(!url.username && !url.password && !url.search && !url.hash && url.pathname === '/');
	return url.origin;
}

function id(value) {
	assert.match(String(value), /^[1-9]\d*$/);
	assert.ok(Number.isSafeInteger(Number(value)) && Number(value) <= 2147483647);
	return Number(value);
}

function elements(html) {
	const nodes = [];
	function visit(node) {
		if (node.tagName) nodes.push(node);
		for (const child of node.childNodes ?? []) visit(child);
	}
	visit(parse(html));
	return nodes;
}
const attr = (node, name) => node.attrs?.find((a) => a.name === name)?.value;
const text = (node) => (node.nodeName === '#text' ? node.value : (node.childNodes ?? []).map(text).join(''));

async function boundedBody(response, maxBytes) {
	if (!response.body) return '';
	const reader = response.body.getReader();
	const decoder = new TextDecoder('utf-8', { fatal: true });
	let result = '',
		bytes = 0;
	try {
		for (;;) {
			const next = await reader.read();
			if (next.done) return result + decoder.decode();
			bytes += next.value.byteLength;
			if (bytes > maxBytes) {
				await reader.cancel();
				throw new Error('Response bound exceeded; no silent truncation');
			}
			result += decoder.decode(next.value, { stream: true });
		}
	} finally {
		reader.releaseLock();
	}
}

export async function runSmoke({
	base,
	canonical = base,
	legacyId = 18,
	nativeId,
	expectedRevision,
	expectCacheHits = false,
	fetcher = fetch,
	maxBytes = 2 * 1024 * 1024,
}) {
	base = origin(base);
	canonical = origin(canonical);
	legacyId = id(legacyId);
	if (nativeId !== undefined) nativeId = id(nativeId);
	assert.equal(nativeId === undefined, expectedRevision === undefined, 'Native ID and expected revision must be supplied together');
	if (expectedRevision !== undefined) expectedRevision = id(expectedRevision);
	assert.ok(Number.isSafeInteger(maxBytes) && maxBytes > 0);
	const checks = [];
	async function check(name, action) {
		try {
			await action();
			checks.push({ name, ok: true });
		} catch {
			// Never print response bodies, cookie values, auth redirects or raw errors.
			checks.push({ name, ok: false });
		}
	}
	async function request(path, { method = 'GET', accept = '*/*' } = {}) {
		assert.ok(['GET', 'HEAD', 'OPTIONS'].includes(method));
		const url = new URL(path, base);
		assert.equal(url.origin, base);
		const response = await fetcher(url.href, {
			method,
			headers: { Accept: accept },
			redirect: 'manual',
			credentials: 'omit',
			signal: AbortSignal.timeout(10_000),
		});
		return { response, body: await boundedBody(response, maxBytes) };
	}
	function publicResponse(result, type, vary = false) {
		const { response } = result;
		assert.equal(response.status, 200);
		assert.ok(response.headers.get('Content-Type')?.startsWith(type));
		assert.equal(response.headers.has('Set-Cookie'), false);
		if (type !== 'application/json') {
			assert.doesNotMatch(response.headers.get('X-Robots-Tag') ?? '', /\b(noindex|none)\b/i);
		} else assert.match(response.headers.get('X-Robots-Tag') ?? '', /noindex/i);
		assert.doesNotMatch(response.headers.get('Cache-Control') ?? '', /no-store|private/i);
		if (vary)
			assert.ok(
				response.headers
					.get('Vary')
					?.toLowerCase()
					.split(/\s*,\s*/)
					.includes('accept'),
			);
	}
	async function document(path, accept, type, canonicalPath = path) {
		const result = await request(path, { accept });
		publicResponse(result, type, true);
		assert.ok(result.response.headers.get('Link')?.includes(`<${canonical}${canonicalPath}>; rel="canonical"`));
		if (type === 'text/html') {
			const nodes = elements(result.body);
			assert.ok(
				nodes.some((n) => n.tagName === 'link' && attr(n, 'rel') === 'canonical' && attr(n, 'href') === `${canonical}${canonicalPath}`),
			);
			assert.ok(
				!nodes.some(
					(n) => n.tagName === 'meta' && attr(n, 'name')?.toLowerCase() === 'robots' && /noindex|none/i.test(attr(n, 'content') ?? ''),
				),
			);
		} else assert.ok(!result.body.trimStart().toLowerCase().startsWith('<!doctype html'));
		return result;
	}
	for (const path of ['/', '/catalog', `/practices/${legacyId}`, '/api-docs']) {
		await check(`representations:${path}`, async () => {
			await document(path, 'text/html', 'text/html');
			await document(path, 'text/html;q=0.1,text/markdown;q=1', 'text/markdown');
			await document(path, 'text/markdown;q=0,text/html;q=1', 'text/html');
			const head = await request(path, { method: 'HEAD', accept: 'text/markdown' });
			publicResponse(head, 'text/markdown', true);
			assert.equal(head.body, '');
		});
	}
	await check('explicit-markdown-and-public-options', async () => {
		const alias = await request(`/practices/${legacyId}.md`, { accept: 'text/html' });
		publicResponse(alias, 'text/markdown');
		assert.ok(alias.body.includes(`Canonical URL: ${canonical}/practices/${legacyId}`));
		const options = await request('/api/v2/entries', { method: 'OPTIONS' });
		assert.equal(options.response.status, 204);
		assert.equal(options.response.headers.get('Access-Control-Allow-Origin'), '*');
		assert.equal(options.body, '');
	});
	await check('published-json-and-v1-boundary', async () => {
		const summary = await request('/api/v2/entries?pageSize=1');
		publicResponse(summary, 'application/json');
		assert.equal(JSON.parse(summary.body).data.length, 1);
		const detail = await request(`/api/v2/entries/${legacyId}`);
		publicResponse(detail, 'application/json');
		assert.equal(JSON.parse(detail.body).data.schemaVersion, 0);
		const legacy = await request('/api/practices');
		publicResponse(legacy, 'application/json');
		const data = JSON.parse(legacy.body).data;
		assert.ok(data.some((entry) => entry.practice_id === legacyId));
		if (nativeId) assert.ok(!data.some((entry) => entry.practice_id === nativeId));
	});
	if (nativeId)
		await check('expected-native-revision-html-markdown-json', async () => {
			const path = `/practices/${nativeId}`;
			const json = await request(`/api/v2/entries/${nativeId}`);
			publicResponse(json, 'application/json');
			const entry = JSON.parse(json.body).data;
			assert.equal(entry.practiceId, nativeId);
			assert.equal(entry.revisionId, expectedRevision);
			assert.equal(entry.schemaVersion, 1);
			const html = await document(path, 'text/html', 'text/html');
			const markdown = await document(path, 'text/markdown', 'text/markdown');
			assert.equal(text(elements(html.body).find((n) => n.tagName === 'h1')), entry.title);
			assert.ok(text(parse(html.body)).includes(`Revision ${expectedRevision}`));
			assert.ok(markdown.body.includes(`Revision: ${expectedRevision}\n`));
			assert.ok(markdown.body.includes(`Canonical URL: ${canonical}${path}`));
			const alias = await request(`${path}.md`, { accept: 'text/html' });
			publicResponse(alias, 'text/markdown');
			assert.equal(alias.body, markdown.body);
		});
	await check('published-discovery-and-skill-digest', async () => {
		const sitemap = await request('/sitemap.xml');
		publicResponse(sitemap, 'application/xml');
		for (const entryId of [legacyId, nativeId].filter(Boolean))
			assert.ok(sitemap.body.includes(`<loc>${canonical}/practices/${entryId}</loc>`));
		for (const loc of sitemap.body.matchAll(/<loc>([^<]+)<\/loc>/g)) {
			const url = new URL(loc[1]);
			assert.equal(url.origin, canonical);
			assert.ok(!url.search && !/\.md$|^\/api\/|^\/dashboard/.test(url.pathname));
		}
		const llms = await request('/llms.txt');
		assert.equal(llms.response.status, 200);
		assert.ok(llms.body.includes(`${canonical}/practices/${legacyId}`));
		const index = await request('/.well-known/agent-skills/index.json');
		assert.equal(index.response.status, 200);
		const skill = JSON.parse(index.body).skills.find((s) => s.name === 'read-practices');
		assert.equal(skill.url, `${canonical}/.well-known/agent-skills/read-practices/SKILL.md`);
		const source = await request('/.well-known/agent-skills/read-practices/SKILL.md');
		assert.equal(source.response.status, 200);
		assert.equal(skill.digest, `sha256:${createHash('sha256').update(source.body).digest('hex')}`);
	});
	await check('anonymous-private-route-denial', async () => {
		const paths = ['/dashboard', '/dashboard/editorial', '/dashboard/api/catalog', '/dashboard/api/practices'];
		if (nativeId) paths.push(`/dashboard/api/catalog/${nativeId}/preview`);
		for (const path of paths) {
			const { response } = await request(path);
			assert.ok([401, 403, 302, 303, 307, 308].includes(response.status));
			assert.notEqual(response.headers.get('Cf-Cache-Status')?.toUpperCase(), 'HIT');
			if (response.status === 401 || response.status === 403)
				assert.match(response.headers.get('Cache-Control') ?? '', /no-store|no-cache/i);
			else {
				const location = new URL(response.headers.get('Location'), base);
				assert.equal(location.protocol, 'https:');
				assert.match(location.hostname, /^[\w-]+\.cloudflareaccess\.com$/i);
				assert.ok(location.pathname.startsWith('/cdn-cgi/access/'));
			}
		}
	});
	if (expectCacheHits)
		await check('live-independent-html-markdown-hits', async () => {
			for (const accept of ['text/html', 'text/markdown']) {
				await request(`/practices/${legacyId}`, { accept });
				const result = await document(`/practices/${legacyId}`, accept, accept);
				assert.equal(result.response.headers.get('Cf-Cache-Status')?.toUpperCase(), 'HIT');
			}
		});
	return {
		scope: 'anonymous-read-only-http',
		ok: checks.every((c) => c.ok),
		checks,
		cacheHitsRequired: expectCacheHits,
		remoteWrites: 'none',
		notVerified: [
			'authenticated-roles-and-retries',
			'purge-propagation',
			'private-copy-recovery',
			'browser-accessibility',
			'release-approval',
		],
	};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	try {
		const { values } = parseArgs({
			options: {
				base: { type: 'string' },
				canonical: { type: 'string' },
				'legacy-id': { type: 'string' },
				'native-id': { type: 'string' },
				'expected-revision': { type: 'string' },
				'expect-cache-hits': { type: 'boolean' },
			},
		});
		assert.ok(values.base, 'An explicitly approved target --base is required');
		const result = await runSmoke({
			base: values.base,
			canonical: values.canonical ?? values.base,
			legacyId: values['legacy-id'] ?? 18,
			nativeId: values['native-id'],
			expectedRevision: values['expected-revision'],
			expectCacheHits: values['expect-cache-hits'] ?? false,
		});
		console.log(JSON.stringify(result, null, 2));
		if (!result.ok) process.exitCode = 1;
	} catch {
		console.error(
			'FAIL read-only smoke check. Supply an approved HTTPS --base; optional --canonical, --native-id plus --expected-revision, --expect-cache-hits. No writes performed.',
		);
		process.exitCode = 1;
	}
}
