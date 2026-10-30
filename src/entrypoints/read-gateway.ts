import { HttpError } from '../http';
import { PUBLIC_CORS } from '../platform/public-http';
import { enforceRateLimit } from '../platform/rate-limit';
import { resolveReadRoute, normalizeApiRequest } from '../read-api';
import { normalizeV2Request } from '../modules/catalog/v2-filters';
import { isPublicContent, normalizeContentRequest } from '../public-content';

// Runs only in the uncached gateway. Do not move rate limiting behind PublicReads' cache.
export async function handleRead(request: Request, env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
	if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: PUBLIC_CORS });
	if (request.method !== 'GET' && request.method !== 'HEAD') {
		throw new HttpError(405, 'Method not allowed', { Allow: 'GET, HEAD, OPTIONS', ...PUBLIC_CORS });
	}
	const route = resolveReadRoute(url.pathname);
	if (!route && !isPublicContent(url.pathname)) throw new HttpError(404, 'API endpoint not found', PUBLIC_CORS);
	await enforceRateLimit(env, `${request.headers.get('CF-Connecting-IP') ?? 'unknown'}:${url.pathname}`);
	const upstream = isPublicContent(url.pathname)
		? normalizeContentRequest(request)
		: route?.version === 2
			? normalizeV2Request(request)
			: normalizeApiRequest(request);
	const response = await ctx.exports.PublicReads.fetch(upstream);
	return request.method === 'HEAD' ? new Response(null, response) : response;
}
