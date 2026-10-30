import { CONTENT_SIGNAL, discoveryLinks } from '../content-rendering';
import { CONTENT_CACHE_CONTROL, CONTENT_CACHE_TAG, EDGE_CACHE_CONTROL } from './cache';

export const CONTENT_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'",
	'Content-Language': 'en',
	'Content-Signal': CONTENT_SIGNAL,
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
	'Access-Control-Expose-Headers': 'Link, Content-Signal, Content-Location',
	'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
};

export function contentResponse(body: BodyInit | null, type: string, canonical: string, markdown: string, vary = false): Response {
	return new Response(body, {
		headers: {
			...CONTENT_HEADERS,
			'Content-Type': `${type}; charset=utf-8`,
			'Cache-Control': CONTENT_CACHE_CONTROL,
			'Cloudflare-CDN-Cache-Control': EDGE_CACHE_CONTROL,
			'Cache-Tag': CONTENT_CACHE_TAG,
			Link: discoveryLinks(canonical, markdown),
			...(vary ? { Vary: 'Accept' } : {}),
		},
	});
}

// Run AFTER Astro/Cloudflare adapter finalization; never buffer its streamed body.
export function finalizeDocument(rendered: Response, canonical: string, markdown: string): Response {
	const response = new Response(rendered.body, rendered);
	for (const [key, value] of Object.entries(CONTENT_HEADERS)) response.headers.set(key, value);
	response.headers.set('Vary', 'Accept');
	response.headers.delete('ETag');
	response.headers.delete('Last-Modified');
	if (response.ok && !response.headers.has('Set-Cookie')) {
		response.headers.set('Cache-Control', CONTENT_CACHE_CONTROL);
		response.headers.set('Cloudflare-CDN-Cache-Control', EDGE_CACHE_CONTROL);
		response.headers.set('Cache-Tag', CONTENT_CACHE_TAG);
		response.headers.set('Link', discoveryLinks(canonical, markdown));
	} else {
		response.headers.set('Cache-Control', 'no-store');
		response.headers.set('Cloudflare-CDN-Cache-Control', 'no-store');
		response.headers.set('X-Robots-Tag', 'noindex');
		response.headers.delete('Cache-Tag');
		response.headers.delete('Link');
	}
	return response;
}
