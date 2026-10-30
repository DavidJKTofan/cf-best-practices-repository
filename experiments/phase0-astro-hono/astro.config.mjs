import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
	output: 'server',
	adapter: cloudflare({ imageService: 'passthrough', remoteBindings: false }),
	session: false,
	build: { inlineStylesheets: 'never' },
	vite: { build: { sourcemap: true } },
});
