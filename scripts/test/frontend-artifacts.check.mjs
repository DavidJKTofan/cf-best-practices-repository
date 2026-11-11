import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { checkPublicArtifacts, files } from '../release/artifacts.mjs';
import { elements, attr } from '../release/markup.mjs';

test('built configuration retains the cache split, scoped assets, and no incidental bindings', async () => {
	const config = JSON.parse(await readFile('dist/server/wrangler.json', 'utf8'));
	assert.equal(config.exports.default.cache.enabled, false);
	assert.equal(config.exports.PublicReads.cache.enabled, true);
	for (const path of ['/', '/catalog', '/catalog.md', '/families/*', '/practices/*', '/dashboard/api/*'])
		assert.ok(config.assets.run_worker_first.includes(path));
	assert.ok(!config.assets.run_worker_first.includes('/*'));
	assert.notEqual(config.d1_databases[0].remote, true);
	assert.equal(config.upload_source_maps, true);
	assert.ok(!config.kv_namespaces?.length);
	assert.ok(!config.images);
	assert.equal(resolve('dist/server', config.assets.directory), resolve('dist/client'));
});

test('actual built public artifacts contain no maps, private modules, pilot fixtures or configuration', async () => {
	await checkPublicArtifacts('dist/client');
	const maps = (await files('dist/server')).filter((p) => p.endsWith('.map'));
	assert.ok(maps.length);
	const mapped = (await Promise.all(maps.map(async (path) => JSON.parse(await readFile(path, 'utf8')).sources ?? []))).flat();
	assert.ok(mapped.some((source) => source.includes('astro-reads.ts')));
	assert.ok(mapped.some((source) => source.includes('practice-creation.ts')));
});

test('reference and static interfaces retain the owner-approved system font stacks without remote fonts', async () => {
	for (const path of ['src/styles/field-guide.css', 'public/style.css']) {
		const css = await readFile(path, 'utf8');
		assert.ok(css.includes("--font: system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;"));
		assert.ok(css.includes("--mono: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;"));
		assert.ok(!/@font-face|fonts\.googleapis|fonts\.gstatic/.test(css));
	}
});

test('built static HTML keeps Markdown and footer links in safe new tabs', async () => {
	for (const path of ['index.html', 'api-docs.html', 'dashboard.html', 'dashboard/editorial.html']) {
		const nodes = elements(await readFile(`dist/client/${path}`, 'utf8'));
		const footer = nodes.find((node) => node.tagName === 'footer');
		assert.ok(footer, path);
		const links = [
			...elements(footer).filter((node) => node.tagName === 'a'),
			...nodes.filter((node) => node.tagName === 'a' && /\.md(?:[?#]|$)/.test(attr(node, 'href') ?? '')),
		];
		for (const link of links) {
			assert.equal(attr(link, 'target'), '_blank', `${path}: ${attr(link, 'href')}`);
			const rel = (attr(link, 'rel') ?? '').split(/\s+/);
			assert.ok(rel.includes('noopener') && rel.includes('noreferrer'), path);
		}
	}
});

test('Level styling is neutral in both interfaces while Domain colors remain distinct', async () => {
	const astro = await readFile('src/styles/field-guide.css', 'utf8');
	const level = astro.match(/\.level-label\s*\{([^}]+)\}/)?.[1];
	assert.ok(level);
	assert.match(level, /--label-bg:\s*var\(--badge-gray-bg\)/);
	assert.match(level, /--label-fg:\s*var\(--badge-gray-fg\)/);
	assert.doesNotMatch(astro, /\.level-label\[data-level|--level-required/);
	for (const domain of ['Security', 'Performance', 'Reliability']) assert.ok(astro.includes(`[data-domain='${domain}']`));
	const legacy = await readFile('public/style.css', 'utf8');
	assert.doesNotMatch(legacy, /td\.col-level::before|--dot:/);
	for (const domain of ['security', 'performance', 'reliability']) assert.ok(legacy.includes(`.domain-${domain}`));
});
