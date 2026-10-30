// Offline configuration checks only. Passing is NOT provisioning/deployment approval.
import assert from 'node:assert/strict';
import { readFile, realpath, stat } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import wrangler from 'wrangler';
import { checkPublicArtifacts } from './artifacts.mjs';

export const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const SOURCE_KEYS = new Set([
	'$schema',
	'name',
	'main',
	'upload_source_maps',
	'compatibility_date',
	'compatibility_flags',
	'assets',
	'exports',
	'observability',
	'vars',
	'd1_databases',
	'routes',
	'workers_dev',
	'preview_urls',
	'ratelimits',
	'account_id',
]);
const UUID = /^[a-f\d]{8}-(?:[a-f\d]{4}-){3}[a-f\d]{12}$/i;
const EXTRA_BINDINGS = [
	'kv_namespaces',
	'r2_buckets',
	'services',
	'workflows',
	'vectorize',
	'hyperdrive',
	'send_email',
	'analytics_engine_datasets',
	'dispatch_namespaces',
	'mtls_certificates',
	'pipelines',
	'secrets_store_secrets',
	'worker_loaders',
	'vpc_services',
	'vpc_networks',
	'ai_search',
	'ai_search_namespaces',
	'agent_memory',
	'artifacts',
	'k2',
	'flagship',
	'unsafe_hello_world',
	'containers',
];

function noRemote(value) {
	if (!value || typeof value !== 'object') return;
	assert.notEqual(value.remote, true, 'Remote development bindings are forbidden');
	for (const child of Object.values(value)) noRemote(child);
}

export function validateStaging(config, production) {
	assert.match(config.name, /^[a-z\d-]+-staging$/, 'Explicit staging Worker name required');
	assert.notEqual(config.name, production.name, 'Staging must not target production Worker');
	assert.equal(config.workers_dev, false, 'Disable alternative workers.dev access');
	assert.equal(config.preview_urls, false, 'Disable alternative preview URLs');
	assert.ok(!config.env || Object.keys(config.env).length === 0, 'Use a single explicit staging config, not environment fallbacks');
	assert.equal(config.routes?.length, 1, 'One explicit staging custom domain required');
	const route = config.routes[0];
	assert.equal(route.custom_domain, true);
	assert.match(route.pattern, /^(?:[a-z\d](?:[a-z\d-]*[a-z\d])?\.)+[a-z]{2,}$/i, 'No wildcard/path staging route');
	assert.ok(
		!(production.routes ?? []).some((r) => (typeof r === 'string' ? r : r.pattern).toLowerCase() === route.pattern.toLowerCase()),
		'Production route collision',
	);
	assert.equal(config.d1_databases?.length, 1, 'Only the explicit isolated DB binding is supported');
	const db = config.d1_databases[0];
	assert.equal(db.binding, 'DB');
	assert.match(db.database_id ?? '', UUID, 'Pre-provisioned staging D1 UUID required; no auto provisioning');
	assert.notEqual(db.database_id, '00000000-0000-0000-0000-000000000000');
	assert.match(db.database_name ?? '', /^[\w-]+-staging$/, 'Explicit staging database name required');
	for (const live of production.d1_databases ?? []) {
		assert.notEqual(db.database_id.toLowerCase(), live.database_id.toLowerCase(), 'Production database collision');
		assert.notEqual(db.database_name, live.database_name, 'Production database name collision');
		if (live.preview_database_id) assert.notEqual(db.database_id.toLowerCase(), live.preview_database_id.toLowerCase());
	}
	assert.ok(!db.preview_database_id || db.preview_database_id === db.database_id, 'No hidden alternate DB target');
	assert.deepEqual(Object.keys(config.vars ?? {}).sort(), ['ACCESS_AUD', 'ACCESS_TEAM_DOMAIN']);
	assert.match(config.vars.ACCESS_AUD, /^[a-f\d]{64}$/i, 'Explicit staging Access audience required');
	assert.notEqual(config.vars.ACCESS_AUD, production.vars.ACCESS_AUD, 'Production Access audience collision');
	const issuer = new URL(config.vars.ACCESS_TEAM_DOMAIN);
	assert.equal(issuer.protocol, 'https:');
	assert.match(issuer.hostname, /^[a-z\d-]+\.cloudflareaccess\.com$/i);
	assert.ok(!issuer.username && !issuer.password && !issuer.port && !issuer.search && !issuer.hash && issuer.pathname === '/');
	assert.deepEqual(config.exports, production.exports, 'Preserve cache-owning entrypoints');
	assert.equal(config.exports?.default?.cache?.enabled, false);
	assert.equal(config.exports?.PublicReads?.cache?.enabled, true);
	assert.equal(config.cache?.enabled ?? false, false, 'No Worker-wide caching');
	assert.equal(config.assets?.binding, 'ASSETS');
	assert.equal(config.assets.not_found_handling, '404-page');
	assert.deepEqual(config.assets.run_worker_first, production.assets.run_worker_first, 'Keep assets free and dynamic routes scoped');
	assert.equal(config.ratelimits?.length, 1);
	assert.equal(config.ratelimits[0].name, 'MY_RATE_LIMITER');
	assert.match(String(config.ratelimits[0].namespace_id), /^\d+$/);
	assert.ok(
		!(production.ratelimits ?? []).some((r) => BigInt(r.namespace_id) === BigInt(config.ratelimits[0].namespace_id)),
		'Production rate-limit namespace collision',
	);
	assert.deepEqual(config.ratelimits[0].simple, production.ratelimits[0].simple);
	assert.equal(config.compatibility_date, production.compatibility_date);
	assert.deepEqual(config.compatibility_flags, production.compatibility_flags);
	assert.deepEqual(config.observability, production.observability);
	assert.equal(config.upload_source_maps, true, 'Retain server-side source maps');
	for (const key of EXTRA_BINDINGS) assert.ok(!config[key]?.length, `Unexpected ${key} resource`);
	for (const key of ['ai', 'images', 'browser', 'version_metadata']) assert.ok(!config[key], `Unexpected ${key} binding`);
	assert.ok(!config.durable_objects?.bindings?.length && !config.queues?.producers?.length && !config.queues?.consumers?.length);
	assert.ok(!config.unsafe?.bindings?.length);
	assert.ok(
		Object.values(config.triggers ?? {}).every((value) => !value || (Array.isArray(value) && value.length === 0)),
		'No staging background triggers',
	);
	noRemote(config);
	return { scope: 'offline-config-only', accessPolicyVerified: false, remoteEffects: 'none' };
}

export function productionConfig() {
	return wrangler.unstable_readConfig({ config: resolve(ROOT, 'wrangler.jsonc') });
}

export async function stagingSource(path) {
	assert.ok(isAbsolute(path), 'CF_STAGING_CONFIG must be an absolute private JSON path');
	const absolute = await realpath(path);
	const fromRoot = relative(ROOT, absolute);
	assert.ok(
		fromRoot.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(fromRoot),
		'Keep deployment-specific staging configuration outside the repository',
	);
	const config = JSON.parse(await readFile(absolute, 'utf8'));
	assert.ok(
		Object.keys(config).every((key) => SOURCE_KEYS.has(key)),
		'Unsupported staging source setting; review rather than inherit hooks/resources',
	);
	validateStaging(config, productionConfig());
	assert.equal(config.main, resolve(ROOT, 'src/astro-worker.ts'), 'Use the actual custom source entrypoint for Astro build');
	assert.equal(config.assets.directory, resolve(ROOT, 'public'), 'Explicit absolute source asset path required');
	assert.equal(config.d1_databases[0].migrations_dir, resolve(ROOT, 'migrations'));
	return absolute;
}

export async function checkGenerated(path) {
	const absolute = await realpath(path);
	const config = JSON.parse(await readFile(absolute, 'utf8'));
	const result = validateStaging(config, productionConfig());
	assert.equal(config.main, 'entry.mjs', 'Check the Astro-generated configuration, never raw source');
	assert.equal(config.assets.directory, '../client');
	assert.ok((await stat(resolve(dirname(absolute), config.main))).isFile());
	assert.ok((await stat(resolve(dirname(absolute), config.assets.directory))).isDirectory());
	await checkPublicArtifacts(resolve(dirname(absolute), config.assets.directory));
	return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	try {
		assert.equal(process.argv.length, 3, 'Usage: npm run release:staging:check -- /private/build/server/wrangler.json');
		await checkGenerated(process.argv[2]);
		console.log('PASS isolated generated staging configuration only. Access/account state and rollout approval remain unverified.');
	} catch {
		console.error(
			'FAIL staging configuration. Check isolation, explicit bindings, scoped cache/assets and generated build paths; no remote action performed.',
		);
		process.exitCode = 1;
	}
}
