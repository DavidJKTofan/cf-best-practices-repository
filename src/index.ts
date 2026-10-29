// Uncached gateway; only PublicReads uses Workers Cache. Other file assets stay asset-first/free.
import { WorkerEntrypoint } from 'cloudflare:workers';
import { HttpError, json, log } from './http';
import { handleCreatePractice } from './practice-creation';
import { EDGE_CACHE_CONTROL, PUBLIC_CORS, READ_ROUTES, enforceRateLimit, normalizeApiRequest } from './read-api';
import { CONTENT_CACHE_TAG, contentError, isPublicContent, normalizeContentRequest, servePublicContent } from './public-content';

async function handleRead(request: Request, env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
	if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: PUBLIC_CORS });
	if (request.method !== 'GET' && request.method !== 'HEAD') {
		throw new HttpError(405, 'Method not allowed', { Allow: 'GET, HEAD, OPTIONS', ...PUBLIC_CORS });
	}
	if (!READ_ROUTES[url.pathname] && !isPublicContent(url.pathname)) throw new HttpError(404, 'API endpoint not found', PUBLIC_CORS);
	await enforceRateLimit(env, `${request.headers.get('CF-Connecting-IP') ?? 'unknown'}:${url.pathname}`);
	const upstream = isPublicContent(url.pathname) ? normalizeContentRequest(request) : normalizeApiRequest(request);
	const response = await ctx.exports.PublicReads.fetch(upstream);
	return request.method === 'HEAD' ? new Response(null, response) : response;
}

export class PublicReads extends WorkerEntrypoint<Env> {
	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		try {
			if (isPublicContent(url.pathname)) return await servePublicContent(request, this.env);
			const route = READ_ROUTES[url.pathname];
			if (!route) throw new HttpError(404, 'API endpoint not found');
			// Cache fills after purges must not cache lagging read-replica data.
			const data = await route.handler(this.env.DB.withSession('first-primary'), url);
			return json(
				{ success: true, data, count: data.length },
				{
					headers: {
						...PUBLIC_CORS,
						'Cache-Control': route.cacheControl,
						'Cloudflare-CDN-Cache-Control': EDGE_CACHE_CONTROL,
						'Cache-Tag': route.tag,
					},
				},
			);
		} catch (err) {
			console.error(err);
			if (isPublicContent(url.pathname)) return contentError(503);
			return json(
				{ success: false, error: 'Internal server error' },
				{ status: 500, headers: { ...PUBLIC_CORS, 'Cache-Control': 'no-store' } },
			);
		}
	}

	// RPC bypasses caching; purges must originate in the cached entrypoint.
	async purgePractices() {
		if (!this.ctx.cache) return { success: true, errors: [] }; // Not emulated by wrangler dev.
		return this.ctx.cache.purge({ tags: [CONTENT_CACHE_TAG] });
	}
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID();
		try {
			if (url.pathname === '/dashboard/api/practices') return await handleCreatePractice(request, env, ctx, url);
			if (url.pathname.startsWith('/api/') || isPublicContent(url.pathname)) return await handleRead(request, env, ctx, url);
			return env.ASSETS.fetch(request);
		} catch (err) {
			if (err instanceof HttpError) {
				log(err.status >= 500 ? 'error' : 'warn', 'request rejected', {
					status: err.status,
					error: err.message,
					method: request.method,
					path: url.pathname,
					requestId,
				});
				return json(
					{ success: false, error: err.message, requestId },
					{ status: err.status, headers: { 'Cache-Control': 'no-store', ...err.headers } },
				);
			}
			console.error(err);
			return json({ success: false, error: 'Internal server error', requestId }, { status: 500, headers: { 'Cache-Control': 'no-store' } });
		}
	},
} satisfies ExportedHandler<Env>;
