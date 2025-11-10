// src/index.js (Production-Ready Cloudflare Worker - JavaScript ES Modules)

// --- Configuration Constants ---
const CONFIG = {
	CACHE_DURATION: 5 * 60 * 1000, // 5 minutes
	MAX_REQUEST_SIZE: 1024 * 1024, // 1MB
	MAX_SEARCH_LENGTH: 200,
	MAX_STRING_LENGTH: 5000,
	ALLOWED_ORIGINS: [
		// 'https://yourdomain.com',
		// 'https://staging.yourdomain.com'
	]
};

// --- Caching Helper ---
const cache = {
	categories: { data: null, timestamp: 0 },
	features: { data: null, timestamp: 0 },
};

// --- Security Helper Functions ---
function sanitizeInput(input, maxLength = CONFIG.MAX_STRING_LENGTH) {
	if (typeof input !== 'string') return input;

	// Truncate to max length
	let sanitized = input.slice(0, maxLength);

	// Remove null bytes
	sanitized = sanitized.replace(/\0/g, '');

	// Trim whitespace
	sanitized = sanitized.trim();

	return sanitized;
}

function isValidId(id) {
	const parsed = parseInt(id, 10);
	return !isNaN(parsed) && parsed > 0 && parsed <= 2147483647; // Max INT
}

function generateRequestId() {
	return crypto.randomUUID();
}

function getCorsHeaders(origin) {
	// If ALLOWED_ORIGINS is empty (development), allow all
	// In production, configure ALLOWED_ORIGINS array
	const allowedOrigin = CONFIG.ALLOWED_ORIGINS.length === 0 ? '*' : CONFIG.ALLOWED_ORIGINS.includes(origin) ? origin : null;

	if (!allowedOrigin) return null;

	return {
		'Access-Control-Allow-Origin': allowedOrigin,
		'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type',
		'Access-Control-Max-Age': '86400',
	};
}

function getSecurityHeaders() {
	return {
		'X-Content-Type-Options': 'nosniff',
		'X-Frame-Options': 'DENY',
		'X-XSS-Protection': '1; mode=block',
		'Referrer-Policy': 'strict-origin-when-cross-origin',
		'Content-Security-Policy': "default-src 'none'",
	};
}

// --- Rate Limiting using Cloudflare's Workers Rate Limiting API ---
async function checkRateLimit(rateLimiter, identifier, requestId) {
	if (!rateLimiter) {
		console.warn(`[${requestId}] Rate limiter binding not configured, skipping rate limit check`);
		return { allowed: true };
	}

	try {
		// Use Cloudflare's rate limiting API
		// limit() returns { success: boolean } where success=true means allowed
		const { success } = await rateLimiter.limit({ key: identifier });

		if (!success) {
			console.warn(`[${requestId}] Rate limit exceeded for ${identifier}`);
			return { allowed: false };
		}

		return { allowed: true };
	} catch (e) {
		console.error(`[${requestId}] Rate limit check error:`, e.message);
		// Fail open - allow request if rate limiter fails
		return { allowed: true };
	}
}

// --- Database Helper Functions ---
async function getCategories(db, requestId) {
	const now = Date.now();
	if (cache.categories.data && now - cache.categories.timestamp < CONFIG.CACHE_DURATION) {
		console.log(`[${requestId}] Returning cached categories`);
		return cache.categories.data;
	}

	console.log(`[${requestId}] Fetching categories from DB`);
	try {
		const stmt = db.prepare('SELECT category_id as id, name FROM Categories ORDER BY name');
		const { results } = await stmt.all();

		cache.categories.data = results ?? [];
		cache.categories.timestamp = now;

		console.log(`[${requestId}] Cached ${cache.categories.data.length} categories`);
		return cache.categories.data;
	} catch (e) {
		console.error(`[${requestId}] DB getCategories Error:`, e.message);
		throw new Error('Failed to fetch categories');
	}
}

async function getFeatures(db, requestId) {
	const now = Date.now();
	if (cache.features.data && now - cache.features.timestamp < CONFIG.CACHE_DURATION) {
		console.log(`[${requestId}] Returning cached features`);
		return cache.features.data;
	}

	console.log(`[${requestId}] Fetching features from DB`);
	try {
		const stmt = db.prepare('SELECT feature_id as id, name FROM CloudflareFeatures ORDER BY name');
		const { results } = await stmt.all();

		cache.features.data = results ?? [];
		cache.features.timestamp = now;

		console.log(`[${requestId}] Cached ${cache.features.data.length} features`);
		return cache.features.data;
	} catch (e) {
		console.error(`[${requestId}] DB getFeatures Error:`, e.message);
		throw new Error('Failed to fetch features');
	}
}

// --- Response Helper Functions ---
function jsonResponse(data, status = 200, additionalHeaders = {}) {
	const headers = {
		'Content-Type': 'application/json; charset=utf-8',
		...getSecurityHeaders(),
		...additionalHeaders,
	};

	return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(message, status = 500, requestId = null) {
	// Log detailed error server-side, return generic message to client
	const errorLog = {
		requestId,
		status,
		message,
		timestamp: new Date().toISOString(),
	};

	console.error('Error Response:', JSON.stringify(errorLog));

	// Don't expose internal error details in production
	const clientMessage = status >= 500 ? 'Internal server error' : message;

	return jsonResponse(
		{
			success: false,
			error: clientMessage,
			requestId,
		},
		status
	);
}

// --- Validation Functions ---
function validateQueryParam(param, validValues) {
	return param && validValues.includes(param);
}

const ENUM_VALUES = {
	domain: ['Security', 'Performance', 'Reliability', 'General'],
	recommendationLevel: ['Mandatory', 'Recommended', 'Optional', 'Situational'],
	impactLevel: ['High', 'Medium', 'Low'],
	difficultyLevel: ['Easy', 'Medium', 'Complex'],
};

function validatePracticeInput(body) {
	const errors = [];

	// Required fields
	const requiredFields = [
		'title',
		'description',
		'domain',
		'recommendation_level',
		'impact_level',
		'category_id',
		'feature_id',
		'source_reference',
	];

	for (const field of requiredFields) {
		if (!body[field]) {
			errors.push(`Missing required field: ${field}`);
		}
	}

	if (errors.length > 0) return { valid: false, errors };

	// Validate string lengths
	if (body.title && body.title.length > 500) {
		errors.push('Title must be 500 characters or less');
	}
	if (body.description && body.description.length > CONFIG.MAX_STRING_LENGTH) {
		errors.push('Description too long');
	}
	if (body.source_reference && body.source_reference.length > 1000) {
		errors.push('Source reference too long');
	}

	// Validate IDs
	if (body.category_id && !isValidId(body.category_id)) {
		errors.push('Invalid category_id');
	}
	if (body.feature_id && !isValidId(body.feature_id)) {
		errors.push('Invalid feature_id');
	}

	// Validate enum values
	if (!validateQueryParam(body.domain, ENUM_VALUES.domain)) {
		errors.push(`Invalid domain. Must be one of: ${ENUM_VALUES.domain.join(', ')}`);
	}
	if (!validateQueryParam(body.recommendation_level, ENUM_VALUES.recommendationLevel)) {
		errors.push(`Invalid recommendation_level. Must be one of: ${ENUM_VALUES.recommendationLevel.join(', ')}`);
	}
	if (!validateQueryParam(body.impact_level, ENUM_VALUES.impactLevel)) {
		errors.push(`Invalid impact_level. Must be one of: ${ENUM_VALUES.impactLevel.join(', ')}`);
	}
	if (body.difficulty_level && !validateQueryParam(body.difficulty_level, ENUM_VALUES.difficultyLevel)) {
		errors.push(`Invalid difficulty_level. Must be one of: ${ENUM_VALUES.difficultyLevel.join(', ')}`);
	}

	return { valid: errors.length === 0, errors };
}

// --- API Handler Functions ---
async function handleGetPractices(url, db, requestId) {
	try {
		const searchParams = url.searchParams;
		const search = searchParams.get('search');
		const categoryId = searchParams.get('categoryId');
		const featureId = searchParams.get('featureId');
		const area = searchParams.get('area');
		const level = searchParams.get('level');
		const impact = searchParams.get('impact');

		// Build query with proper parameterization
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

		// Sanitize and validate search input
		if (search) {
			const sanitizedSearch = sanitizeInput(search, CONFIG.MAX_SEARCH_LENGTH);
			if (sanitizedSearch.length > 0) {
				conditions.push(
					'(bp.title LIKE ? OR bp.description LIKE ? OR bp.expressions_configuration_details LIKE ? OR bp.prerequisites LIKE ? OR bp.notes LIKE ?)'
				);
				const searchTerm = `%${sanitizedSearch}%`;
				params.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
			}
		}

		// Validate and add ID filters
		if (categoryId && isValidId(categoryId)) {
			conditions.push('bp.category_id = ?');
			params.push(parseInt(categoryId, 10));
		}

		if (featureId && isValidId(featureId)) {
			conditions.push('bp.feature_id = ?');
			params.push(parseInt(featureId, 10));
		}

		// Validate enum filters
		if (area && validateQueryParam(area, ENUM_VALUES.domain)) {
			conditions.push('bp.domain = ?');
			params.push(area);
		}

		if (level && validateQueryParam(level, ENUM_VALUES.recommendationLevel)) {
			conditions.push('bp.recommendation_level = ?');
			params.push(level);
		}

		if (impact && validateQueryParam(impact, ENUM_VALUES.impactLevel)) {
			conditions.push('bp.impact_level = ?');
			params.push(impact);
		}

		if (conditions.length > 0) {
			query += ' WHERE ' + conditions.join(' AND ');
		}

		query += ' ORDER BY bp.domain, category_name, bp.title';

		console.log(`[${requestId}] Executing query with ${params.length} parameters`);

		const stmt = db.prepare(query).bind(...params);
		const { results } = await stmt.all();

		console.log(`[${requestId}] Query returned ${results?.length ?? 0} results`);

		return jsonResponse({
			success: true,
			data: results ?? [],
			count: results?.length ?? 0,
		});
	} catch (e) {
		console.error(`[${requestId}] Query error:`, e.message, e.stack);
		throw e;
	}
}

async function handleCreatePractice(request, db, requestId) {
	try {
		// Check content length
		const contentLength = request.headers.get('content-length');
		if (contentLength && parseInt(contentLength) > CONFIG.MAX_REQUEST_SIZE) {
			return errorResponse('Request body too large', 413, requestId);
		}

		const body = await request.json();

		// Validate input
		const validation = validatePracticeInput(body);
		if (!validation.valid) {
			console.warn(`[${requestId}] Validation failed:`, validation.errors);
			return errorResponse(validation.errors.join('; '), 400, requestId);
		}

		// Sanitize string inputs
		const sanitizedData = {
			title: sanitizeInput(body.title, 500),
			description: sanitizeInput(body.description),
			domain: body.domain,
			category_id: parseInt(body.category_id, 10),
			feature_id: parseInt(body.feature_id, 10),
			recommendation_level: body.recommendation_level,
			impact_level: body.impact_level,
			difficulty_level: body.difficulty_level || null,
			prerequisites: body.prerequisites ? sanitizeInput(body.prerequisites) : null,
			expressions_configuration_details: body.expressions_configuration_details
				? sanitizeInput(body.expressions_configuration_details)
				: null,
			source_reference: sanitizeInput(body.source_reference, 1000),
			notes: body.notes ? sanitizeInput(body.notes) : null,
		};

		const query = `
      INSERT INTO BestPractices (
        title, description, domain, category_id, feature_id,
        recommendation_level, impact_level, difficulty_level,
        prerequisites, expressions_configuration_details,
        source_reference, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

		const params = [
			sanitizedData.title,
			sanitizedData.description,
			sanitizedData.domain,
			sanitizedData.category_id,
			sanitizedData.feature_id,
			sanitizedData.recommendation_level,
			sanitizedData.impact_level,
			sanitizedData.difficulty_level,
			sanitizedData.prerequisites,
			sanitizedData.expressions_configuration_details,
			sanitizedData.source_reference,
			sanitizedData.notes,
		];

		console.log(`[${requestId}] Creating new practice: ${sanitizedData.title}`);

		const result = await db
			.prepare(query)
			.bind(...params)
			.run();

		console.log(`[${requestId}] Practice created successfully`);

		return jsonResponse(
			{
				success: true,
				message: 'Practice created successfully',
				id: result.meta?.last_row_id,
			},
			201
		);
	} catch (e) {
		if (e instanceof SyntaxError) {
			return errorResponse('Invalid JSON in request body', 400, requestId);
		}
		console.error(`[${requestId}] Error creating practice:`, e.message, e.stack);
		throw e;
	}
}

// --- Main Worker Fetch Handler ---
export default {
	async fetch(request, env, ctx) {
		const requestId = generateRequestId();
		const url = new URL(request.url);
		const pathname = url.pathname;
		const method = request.method;
		const db = env.DB;
		const rateLimiter = env.MY_RATE_LIMITER; // Rate Limiter binding

		const startTime = Date.now();

		// Log request
		console.log(`[${requestId}] ${method} ${pathname} - Start`);

		try {
			// Validate database binding
			if (!db) {
				console.error(`[${requestId}] Database binding not found`);
				return errorResponse('Database unavailable', 503, requestId);
			}

			// Rate limiting using Cloudflare's Workers Rate Limiting API
			const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
			const rateLimitKey = `${clientIp}:${pathname}`;
			const rateLimit = await checkRateLimit(rateLimiter, rateLimitKey, requestId);

			if (!rateLimit.allowed) {
				return jsonResponse(
					{
						success: false,
						error: 'Rate limit exceeded. Please try again later.',
						requestId,
					},
					429,
					{
						'Retry-After': '60', // Suggest retry after 60 seconds
					}
				);
			}

			// Get CORS headers
			const origin = request.headers.get('Origin');
			const corsHeaders = getCorsHeaders(origin);

			// Handle CORS preflight
			if (method === 'OPTIONS') {
				if (!corsHeaders) {
					return new Response(null, { status: 403 });
				}
				return new Response(null, {
					status: 204,
					headers: {
						...corsHeaders,
						...getSecurityHeaders(),
					},
				});
			}

			// Apply CORS check for API requests
			if (pathname.startsWith('/api/') && CONFIG.ALLOWED_ORIGINS.length > 0 && !corsHeaders) {
				return errorResponse('Origin not allowed', 403, requestId);
			}

			let response;

			// Route API requests
			if (pathname === '/api/practices' && method === 'GET') {
				response = await handleGetPractices(url, db, requestId);
			} else if (pathname === '/api/practices' && method === 'POST') {
				response = await handleCreatePractice(request, db, requestId);
			} else if (pathname === '/api/categories' && method === 'GET') {
				const categories = await getCategories(db, requestId);
				response = jsonResponse({ success: true, data: categories });
			} else if (pathname === '/api/features' && method === 'GET') {
				const features = await getFeatures(db, requestId);
				response = jsonResponse({ success: true, data: features });
			} else if (pathname.startsWith('/api/')) {
				// API endpoint not found
				response = errorResponse('API endpoint not found', 404, requestId);
			} else {
				// Non-API paths - let static asset handler take over
				console.log(`[${requestId}] Non-API path, returning 404 (static assets would be handled by [site] config)`);
				response = new Response('Not Found', { status: 404 });
			}

			// Add CORS headers to response if applicable
			if (corsHeaders && pathname.startsWith('/api/')) {
				const newHeaders = new Headers(response.headers);
				Object.entries(corsHeaders).forEach(([key, value]) => {
					newHeaders.set(key, value);
				});
				response = new Response(response.body, {
					status: response.status,
					statusText: response.statusText,
					headers: newHeaders,
				});
			}

			// Add request ID header
			const newHeaders = new Headers(response.headers);
			newHeaders.set('X-Request-ID', requestId);

			response = new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders,
			});

			const duration = Date.now() - startTime;
			console.log(`[${requestId}] ${method} ${pathname} - ${response.status} (${duration}ms)`);

			return response;
		} catch (e) {
			console.error(`[${requestId}] Unhandled error:`, e.message, e.stack);
			return errorResponse('Internal server error', 500, requestId);
		}
	},
};

console.log('Production Cloudflare Worker initialized');
