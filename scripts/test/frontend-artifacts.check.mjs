import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { checkPublicArtifacts, files } from '../release/artifacts.mjs';

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
