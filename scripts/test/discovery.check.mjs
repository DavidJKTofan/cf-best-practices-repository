import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const root = new URL('../../', import.meta.url);
const source = await readFile(new URL('public/webmcp.js', root), 'utf8');
async function browser(supported = true) {
	const tools = [];
	const calls = [];
	const sandbox = {
		document: supported ? { modelContext: { registerTool: async (tool) => tools.push(tool) } } : {},
		navigator: {},
		location: { origin: 'https://catalog.example.com' },
		URL,
		AbortController,
		console,
		addEventListener: () => {},
		fetch: async (url, options) => {
			calls.push({ url, options });
			return Response.json({ success: true, data: [], links: { next: null } });
		},
	};
	await vm.runInNewContext(`(async () => { ${source}\n })()`, sandbox);
	return { tools, calls };
}
test('WebMCP is optional and preserves the old read-only tool alongside bounded v2 discovery', async () => {
	assert.equal((await browser(false)).tools.length, 0);
	const { tools, calls } = await browser();
	assert.deepEqual(
		tools.map((tool) => tool.name),
		['search_cloudflare_practices', 'search_cloudflare_catalog'],
	);
	await tools[0].execute({ search: 'WAF' });
	assert.equal(calls[0].url.pathname, '/api/practices');
	await tools[1].execute({ q: '界'.repeat(201), family: 'cloudflare-one', page: 2, pageSize: 5 });
	assert.equal(calls[1].url.pathname, '/api/v2/entries');
	assert.equal([...calls[1].url.searchParams.get('q')].length, 200);
	assert.equal(calls[1].url.searchParams.get('family'), 'cloudflare-one');
	assert.equal(calls[1].url.searchParams.get('page'), '2');
	assert.equal(calls[1].options.method, undefined);
	assert.equal(calls[1].options.body, undefined);
	for (const input of [[], null, { q: 3 }, { page: 0 }, { pageSize: 51 }]) await assert.rejects(tools[1].execute(input));
});
test('all OpenAPI references resolve locally; discoverable operation IDs are unique', async () => {
	const documents = new Map();
	for (const name of ['openapi.json', 'openapi-v2.json', 'openapi-editorial.json'])
		documents.set(name, JSON.parse(await readFile(new URL(`public/${name}`, root), 'utf8')));
	const ids = new Set();
	function walk(value, name) {
		if (!value || typeof value !== 'object') return;
		if (value.$ref) {
			const [file, pointer] = value.$ref.split('#');
			let target = documents.get(file ? file.replace(/^\.\//, '') : name);
			assert.ok(target, `Missing reference file: ${value.$ref}`);
			for (const key of (pointer ?? '').split('/').slice(1)) target = target?.[key.replace(/~1/g, '/').replace(/~0/g, '~')];
			assert.notEqual(target, undefined, `Broken reference: ${value.$ref}`);
		}
		if (value.operationId) {
			assert.ok(!ids.has(value.operationId), `Duplicate operation: ${value.operationId}`);
			ids.add(value.operationId);
		}
		for (const child of Object.values(value)) walk(child, name);
	}
	for (const [name, document] of documents) walk(document, name);
	assert.equal(ids.size, 17);
	const manifest = JSON.parse(await readFile(new URL('public/.well-known/ai-catalog.json', root), 'utf8'));
	assert.equal(new Set(manifest.entries.map((entry) => entry.identifier)).size, manifest.entries.length);
});

test('auth.md has a discoverable heading and honestly documents anonymous reads without invented registration', async () => {
	const auth = await readFile(new URL('public/auth.md', root), 'utf8');
	assert.match(auth, /^# .*auth\.md/i);
	assert.match(auth, /no authentication or agent registration/);
	assert.match(auth, /does not operate an OAuth authorization server/);
	assert.match(auth, /never `\/api\/v2\/\*`/);
});
