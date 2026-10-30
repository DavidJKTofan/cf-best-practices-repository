import { handle } from '@astrojs/cloudflare/handler';
import { PublicReads as LegacyPublicReads } from '../../../../src/index';
import { contentError } from '../../../../src/public-content';
import { discoveryLinks } from '../../../../src/content-rendering';

// Preserve the legacy read/purge implementation; replace only HTML presentation in this proof.
export class PublicReads extends LegacyPublicReads {
	override async purgePractices() {
		const result = await super.purgePractices();
		// Local evidence of RPC dispatch only; ctx.cache is NOT emulated here.
		console.log(JSON.stringify({ message: 'phase0 purge RPC', cacheEmulated: Boolean(this.ctx.cache) }));
		return result;
	}

	override async fetch(request: Request): Promise<Response> {
		const path = new URL(request.url).pathname;
		const html = request.headers.get('Accept') !== 'text/markdown';
		if (!html || (path !== '/' && !/^\/practices\/[1-9]\d*$/.test(path))) return super.fetch(request);
		try {
			const rendered = await handle(request, this.env, this.ctx);
			const response = new Response(rendered.body, rendered);
			// Apply policy AFTER adapter finalization. Do not buffer Astro's streamed body.
			response.headers.set('X-Phase0-Renderer', 'astro');
			response.headers.set('Content-Signal', 'search=yes, ai-input=yes, ai-train=no');
			response.headers.set('Vary', 'Accept');
			response.headers.set('X-Content-Type-Options', 'nosniff');
			response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
			response.headers.set('Content-Security-Policy', "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'");
			response.headers.set('Access-Control-Allow-Origin', '*');
			response.headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
			response.headers.set('Access-Control-Expose-Headers', 'Link, Content-Signal, Content-Location');
			response.headers.set('Content-Language', 'en');
			response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
			response.headers.set('Cache-Control', response.ok ? 'public, max-age=60, stale-while-revalidate=600' : 'no-store');
			response.headers.set('Cloudflare-CDN-Cache-Control', response.ok ? 'public, max-age=3600, stale-while-revalidate=86400' : 'no-store');
			if (response.ok && !response.headers.has('Set-Cookie')) {
				response.headers.set('Cache-Tag', 'practices');
				response.headers.set('Link', discoveryLinks(path, path === '/' ? '/index.md' : `${path}.md`));
			} else {
				response.headers.set('Cache-Control', 'no-store');
				response.headers.set('Cloudflare-CDN-Cache-Control', 'no-store');
				response.headers.set('X-Robots-Tag', 'noindex');
			}
			response.headers.delete('ETag');
			response.headers.delete('Last-Modified');
			return response;
		} catch (err) {
			console.error(err);
			return contentError(503);
		}
	}
}
