// src/index.js (Vanilla Cloudflare Worker - JavaScript ES Modules)
// --- Caching Helper (Plain JavaScript - Reused) ---
const cache = {
	categories: { data: null, timestamp: 0 },
	features: { data: null, timestamp: 0 },
};
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

async function getCategories(db) {
	const now = Date.now();
	if (cache.categories.data && now - cache.categories.timestamp < CACHE_DURATION) {
		return cache.categories.data;
	}
	console.log('Fetching categories from DB');
	try {
		const { results } = await db.prepare('SELECT category_id as id, name FROM Categories ORDER BY name').all();
		cache.categories.data = results ?? [];
		cache.categories.timestamp = now;
		return cache.categories.data;
	} catch (e) {
		console.error('DB getCategories Error:', e.message);
		throw new Error('Failed to fetch categories'); // Re-throw for handling upstream
	}
}

async function getFeatures(db) {
	const now = Date.now();
	if (cache.features.data && now - cache.features.timestamp < CACHE_DURATION) {
		return cache.features.data;
	}
	console.log('Fetching features from DB');
	try {
		const { results } = await db.prepare('SELECT feature_id as id, name FROM CloudflareFeatures ORDER BY name').all();
		cache.features.data = results ?? [];
		cache.features.timestamp = now;
		return cache.features.data;
	} catch (e) {
		console.error('DB getFeatures Error:', e.message);
		throw new Error('Failed to fetch features'); // Re-throw
	}
}

// --- Utility Functions ---
function jsonResponse(data, status = 200) {
	// Basic CORS headers included - adjust origins if needed for production
	const headers = {
		'Content-Type': 'application/json',
		'Access-Control-Allow-Origin': '*', // Allow all origins (adjust for production)
		'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS', // Allow relevant methods
		'Access-Control-Allow-Headers': 'Content-Type',
	};
	return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(message, status = 500, details = null) {
	console.error(`Error Response (${status}): ${message}`, details ? JSON.stringify(details) : '');
	return jsonResponse({ success: false, error: message, details: details }, status);
}

// --- Validate parameters against schema constraints ---
function validateQueryParam(param, validValues) {
	return param && validValues.includes(param);
}

// --- Worker Fetch Handler ---
export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const pathname = url.pathname;
		const method = request.method;
		const db = env.DB; // Access D1 binding from environment

		// Handle CORS preflight requests (OPTIONS) - Basic example
		if (method === 'OPTIONS') {
			return new Response(null, {
				headers: {
					'Access-Control-Allow-Origin': '*', // Match origins with jsonResponse
					'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type', // Or specify requested headers
					'Access-Control-Max-Age': '86400', // Cache preflight response for 1 day
				},
			});
		}

		// Only handle GET requests for API endpoints
		if (method !== 'GET') {
			// Let non-GET requests for non-API paths fall through for static asset handling
			if (!pathname.startsWith('/api/')) {
				return new Response('Method Not Allowed (Implicit Static Fallback)', { status: 405 }); // Should be handled by static site logic
			}
			// Explicitly disallow non-GET for API routes
			return errorResponse('Method Not Allowed', 405);
		}

		// --- API Routing ---
		if (pathname === '/api/practices') {
			try {
				const searchParams = url.searchParams;
				const search = searchParams.get('search');
				const categoryId = searchParams.get('categoryId');
				const featureId = searchParams.get('featureId');
				const area = searchParams.get('area');
				const level = searchParams.get('level');

				// Validate parameters based on schema constraints
				const validAreas = ['Security', 'Performance', 'Reliability', 'General'];
				const validLevels = ['Mandatory', 'Recommended', 'Optional', 'Situational'];

				let query = `
			SELECT
			  bp.practice_id, bp.title, bp.description, bp.domain,
			  cat.name AS category_name,
			  cf.name AS feature_name, cf.feature_url,
			  bp.recommendation_level, bp.impact_level, bp.difficulty_level,
			  bp.prerequisites, bp.expressions_configuration_details,
			  bp.source_reference, bp.notes, bp.updated_at
			FROM BestPractices bp
			LEFT JOIN Categories cat ON bp.category_id = cat.category_id
			LEFT JOIN CloudflareFeatures cf ON bp.feature_id = cf.feature_id
		  `;

				const conditions = [];
				const params = [];

				if (search) {
					conditions.push('(bp.title LIKE ? OR bp.description LIKE ? OR bp.expressions_configuration_details LIKE ?)');
					const searchTerm = `%${search}%`;
					params.push(searchTerm, searchTerm, searchTerm);
				}

				if (categoryId) {
					conditions.push('bp.category_id = ?');
					const id = parseInt(categoryId, 10);
					if (!isNaN(id)) params.push(id);
					else conditions.pop();
				}

				if (featureId) {
					conditions.push('bp.feature_id = ?');
					const id = parseInt(featureId, 10);
					if (!isNaN(id)) params.push(id);
					else conditions.pop();
				}

				if (area && validateQueryParam(area, validAreas)) {
					conditions.push('bp.domain = ?');
					params.push(area);
				}

				if (level && validateQueryParam(level, validLevels)) {
					conditions.push('bp.recommendation_level = ?');
					params.push(level);
				}

				if (conditions.length > 0) {
					query += ' WHERE ' + conditions.join(' AND ');
				}

				query += ' ORDER BY bp.domain, category_name, bp.title';

				console.log(`Executing query: ${query.replace(/\s+/g, ' ')} with params: ${JSON.stringify(params)}`);
				const stmt = db.prepare(query).bind(...params);
				const { results } = await stmt.all();

				return jsonResponse({ success: true, data: results ?? [] });
			} catch (e) {
				const errorMessage = e instanceof Error ? e.message : String(e);
				return errorResponse('Failed to query database', 500, errorMessage);
			}
		} else if (pathname === '/api/categories') {
			try {
				const categories = await getCategories(db);
				return jsonResponse({ success: true, data: categories });
			} catch (e) {
				const errorMessage = e instanceof Error ? e.message : String(e);
				return errorResponse('Failed to query categories', 500, errorMessage);
			}
		} else if (pathname === '/api/features') {
			try {
				const features = await getFeatures(db);
				return jsonResponse({ success: true, data: features });
			} catch (e) {
				const errorMessage = e instanceof Error ? e.message : String(e);
				return errorResponse('Failed to query features', 500, errorMessage);
			}
		}

		// If the request is for an API path but not matched above, return 404
		if (pathname.startsWith('/api/')) {
			return errorResponse('API Endpoint Not Found', 404);
		}

		// IMPORTANT: For non-API paths (like '/', '/style.css', '/app.js'),
		// DO NOT return a response here. By returning nothing (undefined),
		// you allow Cloudflare to check the [site] configuration in wrangler.toml
		// and serve the static assets from the './public' directory.
		// If you returned a 404 here for '/', the static assets would never be served.
		console.log(`Path "${pathname}" not handled by API routes, allowing static asset handler.`);
		// Implicitly return undefined, letting the static asset handler take over.
	},
};

console.log('Vanilla Worker initialized (Plain JavaScript ES Modules)');
