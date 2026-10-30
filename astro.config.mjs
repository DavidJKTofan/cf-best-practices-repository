import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import { stagingSource } from './scripts/release/staging.mjs';

// Opt-in private staging config is validated before the adapter can use it.
// Separate output prevents a staging build from replacing production artifacts.
const staging = process.env.CF_STAGING_CONFIG ? await stagingSource(process.env.CF_STAGING_CONFIG) : undefined;
if (staging && process.env.CLOUDFLARE_ENV) throw new Error('Do not combine CF_STAGING_CONFIG with implicit CLOUDFLARE_ENV selection');

export default defineConfig({
	output: 'server',
	outDir: staging ? './dist-staging' : './dist',
	adapter: cloudflare({ imageService: 'passthrough', remoteBindings: false, ...(staging ? { configPath: staging } : {}) }),
	session: false,
	trailingSlash: 'never',
	build: { inlineStylesheets: 'never' },
	vite: { build: { sourcemap: true } },
});
