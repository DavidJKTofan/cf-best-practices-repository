import { Hono } from 'hono';
import { handleCreatePractice } from '../practice-creation';
import { handleCatalogEditorial } from './catalog-editorial';
import type { RequestScope, RouterEnv } from './request-scope';

export function editorialRoutes({ request, env, ctx, url }: RequestScope): Hono<RouterEnv> {
	const routes = new Hono<RouterEnv>();
	// The command owns POST-only semantics, Access, bounded validation, durable receipts and purge attempts.
	routes.all('/dashboard/api/practices', () => handleCreatePractice(request, env, ctx, url));
	routes.all('/dashboard/api/catalog', () => handleCatalogEditorial({ request, env, ctx, url }));
	routes.all('/dashboard/api/catalog/*', () => handleCatalogEditorial({ request, env, ctx, url }));
	return routes;
}
