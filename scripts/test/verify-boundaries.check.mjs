import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBoundaries } from '../verify-boundaries.mjs';

test('allows server dependencies, generated Env use and local browser modules', () => {
	assert.deepEqual(
		checkBoundaries({
			'src/index.ts': "export { PublicReads } from './entrypoints/public-reads'; import { Hono } from 'hono'; const env: Env = {} as Env;",
			'src/entrypoints/public-reads.ts': "import { WorkerEntrypoint } from 'cloudflare:workers';",
			'public/index.html': '<script src="/app.js" type="module"></script><script type="application/ld+json">{}</script>',
			'public/app.js': "import { render } from './render.js'; import('./render.js');",
			'public/render.js': 'export const render = () => {};',
		}),
		[],
	);
});

test('rejects server imports of browser assets, experiments and tests', () => {
	for (const specifier of ['../public/app.js', '../experiments/proof.ts', '../test/index.js']) {
		assert.match(checkBoundaries({ 'src/index.ts': `import '${specifier}';` }).join('\n'), /crosses the src\/ boundary/);
	}
});

test('checks re-exports, type imports, require and dynamic imports', () => {
	for (const source of [
		"export * from '../src/access.ts';",
		"type Secret = import('../src/access.ts').Secret;",
		"import server = require('../src/access.ts');",
		"const server = require('../src/access.ts');",
		"import('../src/access.ts');",
		'import(`../src/access.ts`);',
	]) {
		assert.match(checkBoundaries({ 'public/app.js': source }).join('\n'), /crosses the public\/ boundary/);
	}
});

test('checks every browser module, including transitive dependencies and inline scripts', () => {
	assert.equal(
		checkBoundaries({
			'public/index.html': '<script>import("../src/access.ts")</script>',
			'public/app.js': "import './render.js';",
			'public/render.js': "import { env } from 'cloudflare:workers';",
		}).length,
		2,
	);
});

test('rejects computed imports, external browser modules and unresolved local imports', () => {
	for (const source of ['import(path)', "import 'node:fs'", "import './missing.js'"]) {
		assert.equal(checkBoundaries({ 'public/app.js': source }).length, 1);
	}
});

test('rejects server source, source maps, SQL, Wrangler config and secret files in public assets', () => {
	for (const file of ['worker.ts', 'worker.js.map', 'seed.sql', 'wrangler.jsonc', '.env', '.dev.vars']) {
		assert.match(checkBoundaries({ [`public/${file}`]: '' }).join('\n'), /must not be published/);
	}
});

test('checks Astro frontmatter and prevents browser script imports of server code', () => {
	assert.deepEqual(
		checkBoundaries({
			'src/pages/index.astro': "---\nimport Layout from '../layouts/Layout.astro';\n---\n<Layout />",
			'src/layouts/Layout.astro': '<slot />',
		}),
		[],
	);
	assert.match(checkBoundaries({ 'src/page.astro': "---\nimport '../test/private.js';\n---\n<p>Example</p>" }).join('\n'), /crosses/);
	assert.match(checkBoundaries({ 'src/page.astro': "<script>import './access.ts';</script>" }).join('\n'), /browser script/);
	assert.match(checkBoundaries({ 'src/page.astro': '<script src="../access.ts"></script>' }).join('\n'), /browser script/);
	assert.match(checkBoundaries({ 'src/page.astro': '<script src="/missing.js"></script>' }).join('\n'), /browser script/);
	assert.deepEqual(checkBoundaries({ 'src/page.astro': '<script src="/theme.js"></script>', 'public/theme.js': '' }), []);
});
