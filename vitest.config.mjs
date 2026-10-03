import { fileURLToPath } from 'node:url';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [
		cloudflareTest(async () => ({
			wrangler: { configPath: './wrangler.jsonc' },
			miniflare: {
				// Test-only binding so test/apply-migrations.js can build the schema from ./migrations
				bindings: { TEST_MIGRATIONS: await readD1Migrations(fileURLToPath(new URL('./migrations', import.meta.url))) },
			},
		})),
	],
	test: {
		setupFiles: ['./test/apply-migrations.js'],
	},
});
