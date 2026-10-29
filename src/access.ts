import { createRemoteJWKSet, jwtVerify } from 'jose';
import { HttpError, log } from './http';

// Only public verification keys are shared across requests, never tokens or identities.
let cachedJwks: { issuer: string; resolve: ReturnType<typeof createRemoteJWKSet> } | undefined;
const LOOPBACK_IPS = new Set(['127.0.0.1', '::1']);

// The local-only opt-in is not a deployed binding; all production bindings use generated Env.
export type RuntimeEnv = Env & { ALLOW_LOCAL_WRITES?: string };

export async function requireAccessIdentity(request: Request, env: RuntimeEnv, url: URL): Promise<{ subject: string; email: string }> {
	// Wrangler rewrites the hostname; require the explicit local opt-in AND a loopback client IP.
	if (env.ALLOW_LOCAL_WRITES === 'true' && LOOPBACK_IPS.has(request.headers.get('CF-Connecting-IP') ?? '')) {
		return { subject: 'local-dev', email: 'local-dev' };
	}
	if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) {
		log('error', 'access not configured', { path: url.pathname });
		throw new HttpError(503, 'Write API is not configured');
	}
	const token = request.headers.get('Cf-Access-Jwt-Assertion');
	if (!token) throw new HttpError(401, 'Authentication required');
	try {
		if (cachedJwks?.issuer !== env.ACCESS_TEAM_DOMAIN) {
			cachedJwks = {
				issuer: env.ACCESS_TEAM_DOMAIN,
				resolve: createRemoteJWKSet(new URL('/cdn-cgi/access/certs', env.ACCESS_TEAM_DOMAIN)),
			};
		}
		const { payload } = await jwtVerify(token, cachedJwks.resolve, {
			issuer: env.ACCESS_TEAM_DOMAIN,
			audience: env.ACCESS_AUD,
			algorithms: ['RS256'],
		});
		const user = typeof payload.sub === 'string' && payload.sub ? payload.sub : null;
		// Access service-token JWTs have an empty sub and a signed common_name claim.
		const service = typeof payload.common_name === 'string' && payload.common_name ? payload.common_name : null;
		const actor = user ?? service;
		if (!actor) throw new Error('Access token has no stable actor identity');
		return {
			subject: JSON.stringify([env.ACCESS_TEAM_DOMAIN, user ? 'user' : 'service', actor]),
			email: typeof payload.email === 'string' ? payload.email : actor,
		};
	} catch (err) {
		log('warn', 'invalid access token', { error: String(err) });
		throw new HttpError(403, 'Invalid or expired access token');
	}
}
