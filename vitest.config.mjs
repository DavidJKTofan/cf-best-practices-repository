import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import wrangler from 'wrangler';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [
		cloudflareTest(async () => ({
			// Framework-independent domain/gateway suite; built Astro is tested separately.
			main: './src/index.ts',
			wrangler: { configPath: './wrangler.jsonc' },
			miniflare: {
				// Test-only binding so test/apply-migrations.js can build the schema from ./migrations
				bindings: {
					TEST_STARTER_SQL: wrangler.unstable_splitSqlQuery(
						await readFile(new URL('./data/phase5/local-starters.sql', import.meta.url), 'utf8'),
					),
					TEST_MIGRATIONS: await readD1Migrations(fileURLToPath(new URL('./migrations', import.meta.url))),
					TEST_CATALOG_SQL: (
						await Promise.all(
							[
								'initial_data.sql',
								'data/copyable-expressions.sql',
								'data/content-review-2026-10-29.sql',
								'data/catalog-taxonomy.sql',
								'data/phase5-products.sql',
							].map(async (path) => wrangler.unstable_splitSqlQuery(await readFile(new URL(path, import.meta.url), 'utf8'))),
						)
					).flat(),
				},
			},
		})),
	],
	test: {
		setupFiles: ['./test/apply-migrations.js'],
	},
});
