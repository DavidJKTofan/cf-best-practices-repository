import { Hono } from 'hono';
import legacy from '../../../src/index';
export { PublicReads } from './entrypoints/public-reads';

export default {
	async fetch(request, env, ctx) {
		// Request-scoped composition: Hono does routing, not Access/validation/SQL.
		// The unchanged gateway still owns normalization, rate limiting and ctx.exports.
		const app = new Hono();
		const forward = () => legacy.fetch(request, env, ctx);
		app.all('/dashboard/api/*', forward);
		app.all('/api/*', forward);
		app.all('*', forward);
		const routed = await app.fetch(request);
		const response = new Response(routed.body, routed);
		response.headers.set('X-Phase0-Gateway', 'hono');
		return response;
	},
} satisfies ExportedHandler<Env>;
