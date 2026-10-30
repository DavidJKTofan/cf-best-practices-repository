import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { parse } from 'parse5';
import { frontendHarness, seedFrontend, starters } from './helpers/frontend-harness.mjs';

let server;
before(
	async () => {
		server = frontendHarness();
		await server.listen();
		const { DB } = await server.getWorker().getEnv();
		await seedFrontend(DB, { starterCollection: true });
	},
	{ timeout: 60_000 },
);
after(async () => {
	await server?.close();
});
const read = async (path, init) => {
	const response = await server.fetch(path, init);
	return { response, text: await response.text() };
};
const prose = (text) => text.replace(/\\([\\`*_{}\[\]<>()#+.!|~-])/g, '$1');
const escaped = (text) => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const textContent = (node) => (node.nodeName === '#text' ? node.value : (node.childNodes ?? []).map(textContent).join(''));
const findAll = (node, predicate) => [
	...(predicate(node) ? [node] : []),
	...(node.childNodes ?? []).flatMap((child) => findAll(child, predicate)),
];
const attribute = (node, name) => node.attrs?.find((attr) => attr.name === name)?.value;

test('two starter family journeys are populated in initial HTML and Markdown, with no pilot duplicates or broader empty hubs', async () => {
	for (const family of ['cloudflare-one', 'developer-platform']) {
		const html = await read(`/families/${family}`);
		const md = await read(`/families/${family}.md`);
		assert.equal(html.response.status, 200);
		assert.match(html.text, /2 matching entries/);
		assert.match(html.text, /class="starter-collection" aria-labelledby="starter-heading"/);
		assert.ok(prose(md.text).includes('## Start here:'));
		const pair = starters.filter((entry) => entry.content.primaryFamily === family);
		const collections = findAll(parse(html.text), (node) => attribute(node, 'class')?.split(/\s+/).includes('starter-collection'));
		assert.equal(collections.length, 1);
		assert.deepEqual(
			findAll(collections[0], (node) => node.tagName === 'a').map((node) => attribute(node, 'href')),
			pair.map((entry) => `/practices/${entry.id}`),
		);
		assert.ok(md.text.indexOf(`/practices/${pair[0].id}`) < md.text.indexOf(`/practices/${pair[1].id}`));
		for (const { id, content } of starters.filter((entry) => entry.content.primaryFamily === family)) {
			assert.ok(html.text.includes(`/practices/${id}`));
			assert.ok(html.text.includes(content.title));
			assert.ok(prose(md.text).includes(content.title));
		}
		assert.ok(!html.text.includes('80000'));
		assert.ok(!(await read(`/families/${family}?q=NO_SUCH_PATTERN`)).text.includes('class="starter-collection"'));
	}
	for (const family of ['network-services', 'platform-operations', 'application-services'])
		assert.equal((await read(`/families/${family}`)).response.status, 404);
});

test('all four starters render complete same-revision HTML/Markdown/JSON and explicit runbook recovery sections', async () => {
	for (const { id, content } of starters) {
		const html = await read(`/practices/${id}`);
		const md = await read(`/practices/${id}.md`);
		const visibleText = textContent(parse(html.text));
		const { data } = await (await server.fetch(`/api/v2/entries/${id}`)).json();
		assert.equal(html.response.status, 200);
		assert.equal(md.response.status, 200);
		assert.deepEqual(data.body, content.body);
		assert.ok(html.text.includes(`Revision ${data.revisionId}`));
		assert.ok(md.text.includes(`Revision: ${data.revisionId}`));
		assert.ok(!data.v1Eligible);
		assert.equal(html.response.headers.get('Cache-Tag'), 'practices');
		assert.equal(html.response.headers.get('Vary'), 'Accept');
		for (const item of content.body.variant ? content.body.successCriteria : content.body.validation) {
			assert.ok(html.text.includes(escaped(item)));
			assert.ok(prose(md.text).includes(item));
		}
		if (content.body.variant) {
			for (const section of ['task', 'symptoms', 'diagnostics', 'safe-changes', 'recovery', 'validation', 'rollback'])
				assert.ok(html.text.includes(`id="${section}"`));
			for (const [key, values] of Object.entries(content.body)) {
				if (key === 'variant') continue;
				for (const value of Array.isArray(values) ? values : [values]) {
					assert.ok(visibleText.includes(value), `${id}: ${key}`);
					assert.ok(prose(md.text).includes(value), `${id}: ${key}`);
				}
			}
		}
		for (const source of content.sources) assert.ok(html.text.includes(source.url) && md.text.includes(source.url));
		const head = await read(`/practices/${id}`, { method: 'HEAD' });
		assert.equal(head.response.status, 200);
		assert.equal(head.text, '');
	}
});

test('starter discovery/export parity includes all published local snapshots but never changes the legacy catalog', async () => {
	for (const path of ['/llms.txt', '/llms-full.txt', '/index.md', '/sitemap.xml']) {
		const { response, text } = await read(path);
		assert.equal(response.status, 200);
		for (const { id } of starters) assert.ok(text.includes(`/practices/${id}`), path);
		assert.ok(!text.includes('/practices/800001'));
	}
	const legacy = await (await server.fetch('/api/practices')).json();
	assert.equal(legacy.count, 119);
	assert.ok(legacy.data.every((entry) => entry.practice_id < 810001));
	const negotiated = await read('/practices/810002', { headers: { Accept: 'text/markdown' } });
	assert.match(negotiated.response.headers.get('Content-Type'), /text\/markdown/);
	assert.match(negotiated.text, /Read-only diagnosis/);
});
