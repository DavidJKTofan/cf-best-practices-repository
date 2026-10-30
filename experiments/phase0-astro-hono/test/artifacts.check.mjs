import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, readdir } from 'node:fs/promises';
import { resolve, relative } from 'node:path';

async function files(directory) {
	const output = [];
	for (const entry of await readdir(directory, { withFileTypes: true })) {
		const path = resolve(directory, entry.name);
		output.push(...(entry.isDirectory() ? await files(path) : [path]));
	}
	return output;
}

test('generated config retains entrypoint cache split, scoped asset routes and local-only bindings', async () => {
	const config = JSON.parse(await readFile('dist/server/wrangler.json', 'utf8'));
	assert.equal(config.exports.default.cache.enabled, false);
	assert.equal(config.exports.PublicReads.cache.enabled, true);
	assert.ok(Array.isArray(config.assets.run_worker_first));
	assert.ok(config.assets.run_worker_first.includes('/practices/*'));
	assert.ok(config.assets.run_worker_first.includes('/dashboard/api/*'));
	assert.ok(!config.assets.run_worker_first.includes('/*'));
	assert.equal(config.d1_databases[0].database_id, '00000000-0000-0000-0000-000000000000');
	assert.notEqual(config.d1_databases[0].remote, true);
	assert.equal(config.upload_source_maps, true);
	assert.ok(!config.routes?.length);
	assert.ok(!config.kv_namespaces?.length, 'sessions must not provision KV');
	assert.ok(!config.images, 'passthrough images must not provision an Images binding');
	const assetRoot = resolve('dist/server', config.assets.directory);
	assert.equal(assetRoot, resolve('dist/client'));
});

test('server source maps exist but public assets contain no server code/maps/configuration', async () => {
	const serverFiles = await files('dist/server');
	const maps = serverFiles.filter((path) => path.endsWith('.map'));
	assert.ok(maps.length > 0, 'Vite must produce server maps, not just set upload_source_maps');
	const sources = (await Promise.all(maps.map(async (path) => JSON.parse(await readFile(path, 'utf8')).sources ?? []))).flat();
	assert.ok(
		sources.some((source) => source.includes('practice-creation.ts')),
		'map should reach legacy code',
	);
	assert.ok(
		sources.some((source) => source.includes('public-reads.ts')),
		'map should reach named entrypoint',
	);
	for (const path of await files('dist/client')) {
		const name = relative(resolve('dist/client'), path);
		assert.ok(!/\.(?:map|ts|sql)$|wrangler|worker-configuration|\.dev\.vars/.test(name), name);
		const content = await readFile(path, 'utf8');
		assert.ok(!/create-practice:v1|PRIVATE KEY|ACCESS_AUD|PracticeCreations/.test(content), name);
	}
});
