import { Hono } from 'hono';
import { editorialRoutes } from '../api/editorial';
import { legacyRoutes } from '../api/legacy';
import { publicRoutes } from '../api/public';
import type { RequestScope, RouterEnv } from '../api/request-scope';
import { HttpError, json, log } from '../http';
import { isPublicContent } from '../public-content';

async function dispatch(scope: RequestScope): Promise<Response> {
	const { request, env, ctx } = scope;
	// Capture the original platform context rather than casting Hono's executionCtx.
	// This also keeps identities/requests out of module-level state.
	const app = new Hono<RouterEnv>({ getPath: (request) => new URL(request.url).pathname });
	app.onError((err) => {
		throw err; // The gateway, not framework defaults, owns the existing error contract.
	});
	app.route('/', editorialRoutes(scope));
	app.route('/', legacyRoutes(scope));
	app.route('/', publicRoutes(scope));
	app.all('*', () => env.ASSETS.fetch(request));
	// Hono otherwise strips every HEAD body, including legacy error/asset responses.
	// Use a GET routing view only; handlers still see the original method/headers/body.
	const routingRequest = request.method === 'HEAD' ? new Request(request.url, { headers: request.headers }) : request;
	return app.fetch(routingRequest, env, ctx);
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID();
		try {
			// Preserve the original asset fast path (including the binding's own async failure semantics).
			if (!url.pathname.startsWith('/dashboard/api/') && !url.pathname.startsWith('/api/') && !isPublicContent(url.pathname)) {
				return env.ASSETS.fetch(request);
			}
			return await dispatch({ request, env, ctx, url });
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
