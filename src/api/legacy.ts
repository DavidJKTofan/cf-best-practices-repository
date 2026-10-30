import { Hono } from 'hono';
import { handleRead } from '../entrypoints/read-gateway';
import type { RequestScope, RouterEnv } from './request-scope';

export function legacyRoutes({ request, env, ctx, url }: RequestScope): Hono<RouterEnv> {
	const routes = new Hono<RouterEnv>();
	// Hono's wildcard also matches bare /api. Historically only /api/ belongs to the read API.
	routes.all('/api/*', (_, next) => (url.pathname.startsWith('/api/') ? handleRead(request, env, ctx, url) : next()));
	return routes;
}
