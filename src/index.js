// src/index.js — Public read API and Access-protected write API for the best practices repository (D1).
// Static assets in ./public are served directly; this Worker only runs for /api/* and /dashboard/api/*.
//
// Caching (https://developers.cloudflare.com/workers/cache/examples/, gateway pattern): the default entrypoint is an
// uncached gateway (keeps static assets free, runs rate limiting and auth on every request) that forwards reads
// to the PublicReads entrypoint, which has Workers Cache enabled in wrangler.jsonc. Cache hits never query D1.
import { WorkerEntrypoint } from 'cloudflare:workers';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const MAX_BODY_BYTES = 64 * 1024;
const MAX_SEARCH_LENGTH = 200;

const ENUMS = {
	domain: ['Security', 'Performance', 'Reliability', 'General'],
	recommendation_level: ['Mandatory', 'Recommended', 'Optional', 'Situational'],
	impact_level: ['High', 'Medium', 'Low'],
	difficulty_level: ['Easy', 'Medium', 'Complex'],
};

const TEXT_LIMITS = {
	title: 500,
	description: 5000,
	prerequisites: 5000,
	expressions_configuration_details: 5000,
	source_reference: 1000,
	notes: 5000,
};

// Transient D1 errors worth retrying (https://developers.cloudflare.com/d1/best-practices/retry-queries/)
const RETRYABLE_D1_ERRORS = ['Network connection lost', 'storage caused object to be reset', 'reset because its code was updated'];

const API_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'X-Robots-Tag': 'noindex, nofollow',
};

// Edge-only TTL for Workers Cache (stripped before responses reach clients). Writes purge the cache, and each
// deployment starts with an empty cache, so this mainly bounds staleness after direct D1 edits.
const EDGE_CACHE_CONTROL = 'public, max-age=3600, stale-while-revalidate=86400';
const PRACTICES_CACHE_TAG = 'practices';

// The read API is public and anonymous, so any origin may read it. Writes are same-origin only.
const PUBLIC_CORS = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, OPTIONS',
	'Access-Control-Max-Age': '86400',
};

const LOOPBACK_IPS = new Set(['127.0.0.1', '::1']);

class HttpError extends Error {
	constructor(status, message, headers = {}) {
		super(message);
		this.status = status;
		this.headers = headers;
	}
}

function json(data, { status = 200, headers = {} } = {}) {
	return Response.json(data, { status, headers: { ...API_HEADERS, ...headers } });
}

function log(level, message, fields = {}) {
	console[level](JSON.stringify({ message, ...fields }));
}

// --- Read handlers -------------------------------------------------------------------------------

const PRACTICES_SQL = `
	SELECT
		bp.practice_id, bp.title, bp.description, bp.domain,
		bp.category_id, cat.name AS category_name,
		bp.feature_id, cf.name AS feature_name, cf.feature_url,
		bp.recommendation_level, bp.impact_level, bp.difficulty_level,
		bp.prerequisites, bp.expressions_configuration_details,
		bp.source_reference, bp.notes, bp.updated_at
	FROM BestPractices bp
	LEFT JOIN Categories cat ON bp.category_id = cat.category_id
	LEFT JOIN CloudflareFeatures cf ON bp.feature_id = cf.feature_id`;

function parseId(value) {
	const id = Number(value);
	return Number.isInteger(id) && id > 0 && id <= 2147483647 ? id : null;
}

async function listPractices(db, url) {
	const params = url.searchParams;
	const conditions = [];
	const bindings = [];

	const search = (params.get('search') ?? '').replace(/\0/g, '').trim().slice(0, MAX_SEARCH_LENGTH);
	if (search) {
		// Escape LIKE wildcards so "rate_limit" matches literally
		const pattern = `%${search.replace(/[\\%_]/g, '\\$&')}%`;
		const columns = ['bp.title', 'bp.description', 'bp.expressions_configuration_details', 'bp.prerequisites', 'bp.notes'];
		conditions.push(`(${columns.map((c) => `${c} LIKE ? ESCAPE '\\'`).join(' OR ')})`);
		bindings.push(...columns.map(() => pattern));
	}

	const categoryId = parseId(params.get('categoryId'));
	if (categoryId) {
		conditions.push('bp.category_id = ?');
		bindings.push(categoryId);
	}

	const featureId = parseId(params.get('featureId'));
	if (featureId) {
		conditions.push('bp.feature_id = ?');
		bindings.push(featureId);
	}

	for (const [param, column, allowed] of [
		['area', 'bp.domain', ENUMS.domain],
		['level', 'bp.recommendation_level', ENUMS.recommendation_level],
		['impact', 'bp.impact_level', ENUMS.impact_level],
	]) {
		const value = params.get(param);
		if (value && allowed.includes(value)) {
			conditions.push(`${column} = ?`);
			bindings.push(value);
		}
	}

	const where = conditions.length ? ` WHERE ${conditions.join(' AND ')}` : '';
	const { results, meta } = await db
		.prepare(`${PRACTICES_SQL}${where} ORDER BY bp.domain, category_name, bp.title`)
		.bind(...bindings)
		.all();

	// rows_read drives D1 cost; served_by_* shows whether read replicas are being used
	log('log', 'd1 query', {
		query: 'practices',
		filtered: conditions.length > 0,
		rows_read: meta.rows_read,
		duration_ms: meta.duration,
		served_by_region: meta.served_by_region,
		served_by_primary: meta.served_by_primary,
	});

	return results;
}

async function listCategories(db) {
	const { results } = await db.prepare('SELECT category_id AS id, name FROM Categories ORDER BY name').all();
	return results;
}

async function listFeatures(db) {
	const { results } = await db.prepare('SELECT feature_id AS id, name, feature_url FROM CloudflareFeatures ORDER BY name').all();
	return results;
}

// cacheControl is what browsers see; the edge uses EDGE_CACHE_CONTROL
const READ_ROUTES = {
	'/api/practices': { handler: listPractices, tag: PRACTICES_CACHE_TAG, cacheControl: 'public, max-age=60, stale-while-revalidate=600' },
	'/api/categories': { handler: listCategories, tag: 'taxonomy', cacheControl: 'public, max-age=300, stale-while-revalidate=3600' },
	'/api/features': { handler: listFeatures, tag: 'taxonomy', cacheControl: 'public, max-age=300, stale-while-revalidate=3600' },
};

async function enforceRateLimit(env, key) {
	if (!env.MY_RATE_LIMITER) return;
	try {
		const { success } = await env.MY_RATE_LIMITER.limit({ key });
		if (!success) {
			log('warn', 'rate limited', { key });
			throw new HttpError(429, 'Rate limit exceeded. Please try again later.', { 'Retry-After': '60' });
		}
	} catch (err) {
		if (err instanceof HttpError) throw err;
		// Fail open: the rate limiter is a soft guard and must not take the API down
		log('error', 'rate limiter error', { error: String(err) });
	}
}

async function handleRead(request, env, ctx, url) {
	if (request.method === 'OPTIONS') {
		return new Response(null, { status: 204, headers: PUBLIC_CORS });
	}
	if (request.method !== 'GET') {
		throw new HttpError(405, 'Method not allowed', { Allow: 'GET, OPTIONS', ...PUBLIC_CORS });
	}

	const route = READ_ROUTES[url.pathname];
	if (!route) throw new HttpError(404, 'API endpoint not found', PUBLIC_CORS);

	// Anonymous API: the client IP is the only actor identifier available
	await enforceRateLimit(env, `${request.headers.get('CF-Connecting-IP') ?? 'unknown'}:${url.pathname}`);

	// Workers Cache sits in front of this call: on a hit, PublicReads.fetch() (and D1) never runs
	return ctx.exports.PublicReads.fetch(request);
}

export class PublicReads extends WorkerEntrypoint {
	// Only reached via handleRead(), which has already validated the method and route
	async fetch(request) {
		const url = new URL(request.url);
		const route = READ_ROUTES[url.pathname];
		try {
			// Sessions API lets reads be served by the nearest read replica once read replication is
			// enabled on the database; without replication every query simply goes to the primary.
			const data = await route.handler(this.env.DB.withSession('first-unconstrained'), url);
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
			// Pass the caught value itself so Workers Issues can group it by exception and stack
			console.error(err);
			return json(
				{ success: false, error: 'Internal server error' },
				{ status: 500, headers: { ...PUBLIC_CORS, 'Cache-Control': 'no-store' } },
			);
		}
	}

	// RPC methods bypass the cache and run inside this entrypoint. Purges are scoped to the calling
	// entrypoint, so the write handler purges PublicReads' cache through this method.
	async purgePractices() {
		// ctx.cache is absent where Workers Cache is unavailable (e.g. `wrangler dev`): nothing to purge
		if (!this.ctx.cache) return { success: true };
		return this.ctx.cache.purge({ tags: [PRACTICES_CACHE_TAG] });
	}
}

async function purgeReadCache(ctx) {
	// A failed purge must not fail the write; cached reads then expire with EDGE_CACHE_CONTROL
	try {
		const result = await ctx.exports.PublicReads.purgePractices();
		if (!result?.success) log('error', 'cache purge failed', { errors: result?.errors });
	} catch (err) {
		log('error', 'cache purge failed', { error: String(err) });
	}
}

// --- Write handler -------------------------------------------------------------------------------

async function requireAccessIdentity(request, env, url) {
	// Local development only: `wrangler dev` has no Access in front of it. Requires an explicit opt-in
	// in .dev.vars AND a loopback client IP, which Cloudflare's edge never sets on real traffic
	// (wrangler dev rewrites request.url to the production hostname, so the URL cannot be used here).
	if (env.ALLOW_LOCAL_WRITES === 'true' && LOOPBACK_IPS.has(request.headers.get('CF-Connecting-IP'))) {
		return { email: 'local-dev' };
	}

	if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) {
		log('error', 'access not configured', { path: url.pathname });
		throw new HttpError(503, 'Write API is not configured');
	}

	const token = request.headers.get('Cf-Access-Jwt-Assertion');
	if (!token) throw new HttpError(401, 'Authentication required');

	// https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
	try {
		const jwks = createRemoteJWKSet(new URL('/cdn-cgi/access/certs', env.ACCESS_TEAM_DOMAIN));
		const { payload } = await jwtVerify(token, jwks, { issuer: env.ACCESS_TEAM_DOMAIN, audience: env.ACCESS_AUD });
		return { email: payload.email ?? payload.sub };
	} catch (err) {
		log('warn', 'invalid access token', { error: String(err) });
		throw new HttpError(403, 'Invalid or expired access token');
	}
}

async function readJsonBody(request) {
	const contentType = request.headers.get('Content-Type') ?? '';
	// Requiring JSON forces a CORS preflight for cross-site requests, which blocks form-based CSRF
	if (!contentType.toLowerCase().startsWith('application/json')) {
		throw new HttpError(415, 'Content-Type must be application/json');
	}
	if (Number(request.headers.get('Content-Length')) > MAX_BODY_BYTES) throw new HttpError(413, 'Request body too large');
	const body = await request.text();
	if (body.length > MAX_BODY_BYTES) throw new HttpError(413, 'Request body too large');
	try {
		return JSON.parse(body);
	} catch {
		throw new HttpError(400, 'Invalid JSON in request body');
	}
}

function validatePractice(body) {
	if (!body || typeof body !== 'object' || Array.isArray(body)) {
		throw new HttpError(400, 'Request body must be a JSON object');
	}

	const errors = [];

	const text = (field, required) => {
		const raw = body[field];
		if (raw !== undefined && raw !== null && typeof raw !== 'string') {
			errors.push(`${field} must be a string`);
			return null;
		}
		const value = (raw ?? '').replace(/\0/g, '').trim();
		if (!value) {
			if (required) errors.push(`${field} is required`);
			return null;
		}
		if (value.length > TEXT_LIMITS[field]) errors.push(`${field} must be at most ${TEXT_LIMITS[field]} characters`);
		return value;
	};

	const oneOf = (field, required) => {
		const value = body[field];
		if (value === undefined || value === null || value === '') {
			if (required) errors.push(`${field} is required`);
			return null;
		}
		if (!ENUMS[field].includes(value)) errors.push(`${field} must be one of: ${ENUMS[field].join(', ')}`);
		return value;
	};

	const id = (field) => {
		const value = parseId(body[field]);
		if (!value) errors.push(`${field} must be a positive integer`);
		return value;
	};

	const practice = {
		title: text('title', true),
		description: text('description', true),
		domain: oneOf('domain', true),
		category_id: id('category_id'),
		feature_id: id('feature_id'),
		recommendation_level: oneOf('recommendation_level', true),
		impact_level: oneOf('impact_level', true),
		difficulty_level: oneOf('difficulty_level', false),
		prerequisites: text('prerequisites', false),
		expressions_configuration_details: text('expressions_configuration_details', false),
		source_reference: text('source_reference', true),
		notes: text('notes', false),
	};

	if (practice.source_reference) {
		let protocol;
		try {
			protocol = new URL(practice.source_reference).protocol;
		} catch {}
		if (protocol !== 'https:' && protocol !== 'http:') errors.push('source_reference must be an http(s) URL');
	}

	if (errors.length) throw new HttpError(400, errors.join('; '));
	return practice;
}

async function withRetry(operation, { attempts = 4, baseDelayMs = 100 } = {}) {
	for (let attempt = 1; ; attempt++) {
		try {
			return await operation();
		} catch (err) {
			const retryable = RETRYABLE_D1_ERRORS.some((m) => String(err).includes(m));
			if (!retryable || attempt >= attempts) throw err;
			// Exponential backoff with full jitter
			const delay = Math.random() * baseDelayMs * 2 ** attempt;
			log('warn', 'retrying d1 write', { attempt, delay_ms: Math.round(delay), error: String(err) });
			await new Promise((resolve) => setTimeout(resolve, delay));
		}
	}
}

async function handleCreatePractice(request, env, ctx, url) {
	if (request.method !== 'POST') throw new HttpError(405, 'Method not allowed', { Allow: 'POST' });

	const identity = await requireAccessIdentity(request, env, url);
	const practice = validatePractice(await readJsonBody(request));
	const columns = Object.keys(practice);

	let result;
	try {
		result = await withRetry(() =>
			env.DB.prepare(`INSERT INTO BestPractices (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`)
				.bind(...Object.values(practice))
				.run(),
		);
	} catch (err) {
		const message = String(err);
		if (message.includes('FOREIGN KEY constraint failed')) throw new HttpError(400, 'Unknown category_id or feature_id');
		if (message.includes('CHECK constraint failed')) throw new HttpError(400, 'One or more fields have an invalid value');
		throw err;
	}

	const id = result.meta.last_row_id;
	log('log', 'practice created', { id, title: practice.title, by: identity.email });
	// Awaited so the dashboard's follow-up read (and permalink) already sees the new row
	await purgeReadCache(ctx);
	return json({ success: true, message: 'Practice created successfully', id }, { status: 201 });
}

// --- Entry point ---------------------------------------------------------------------------------

/** @type {ExportedHandler<Env>} */
export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID();

		try {
			if (url.pathname === '/dashboard/api/practices') return await handleCreatePractice(request, env, ctx, url);
			if (url.pathname.startsWith('/api/')) return await handleRead(request, env, ctx, url);
			// Anything else that reaches the Worker falls back to static assets (and public/404.html)
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

			// Pass the caught value itself so Workers Issues can group it by exception and stack
			// (method, path, and Ray ID are already in the invocation log)
			console.error(err);
			return json({ success: false, error: 'Internal server error', requestId }, { status: 500, headers: { 'Cache-Control': 'no-store' } });
		}
	},
};
