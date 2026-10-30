import { Hono } from 'hono';
import { handleRead } from '../entrypoints/read-gateway';
import { isPublicContent } from '../public-content';
import type { RequestScope, RouterEnv } from './request-scope';

export function publicRoutes({ request, env, ctx, url }: RequestScope): Hono<RouterEnv> {
	const routes = new Hono<RouterEnv>();
	const read = () => handleRead(request, env, ctx, url);
	for (const path of ['/', '/index.md', '/llms.txt', '/llms-full.txt', '/sitemap.xml', '/api-docs']) routes.all(path, read);
	for (const path of ['/catalog', '/catalog.md']) routes.all(path, read);
	routes.all('/families/*', (_, next) => (isPublicContent(url.pathname) ? read() : next()));
	// Keep the existing numeric-ID predicate; invalid paths still fall through to static assets.
	routes.all('/practices/*', (_, next) => (isPublicContent(url.pathname) ? read() : next()));
	return routes;
}
