import { WorkerEntrypoint } from 'cloudflare:workers';
import { HttpError, json } from '../http';
import { EDGE_CACHE_CONTROL, purgePractices } from '../platform/cache';
import { PUBLIC_CORS } from '../platform/public-http';
import { resolveReadRoute } from '../read-api';
import { contentError, isPublicContent, servePublicContent } from '../public-content';

export class PublicReads extends WorkerEntrypoint<Env> {
	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		try {
			if (isPublicContent(url.pathname)) return await servePublicContent(request, this.env);
			const route = resolveReadRoute(url.pathname);
			if (!route) throw new HttpError(404, 'API endpoint not found');
			// Cache fills after purges must not cache lagging read-replica data.
			const db = this.env.DB.withSession('first-primary');
			const data =
				route.version === 2
					? await route.handler(db, url)
					: await route.handler(db, url).then((data) => ({ success: true, data, count: data.length }));
			return json(data, {
				headers: {
					...PUBLIC_CORS,
					'Cache-Control': route.cacheControl,
					'Cloudflare-CDN-Cache-Control': EDGE_CACHE_CONTROL,
					'Cache-Tag': route.tag,
				},
			});
		} catch (err) {
			console.error(err);
			if (isPublicContent(url.pathname)) return contentError(503);
			if (url.pathname.startsWith('/api/v2/') && err instanceof HttpError) {
				return json(
					{ success: false, error: err.message },
					{ status: err.status, headers: { ...PUBLIC_CORS, 'Cache-Control': 'no-store' } },
				);
			}
			return json(
				{ success: false, error: 'Internal server error' },
				{ status: 500, headers: { ...PUBLIC_CORS, 'Cache-Control': 'no-store' } },
			);
		}
	}

	// RPC bypasses caching; purges must originate in the cached entrypoint.
	async purgePractices() {
		return purgePractices(this.ctx);
	}
}
