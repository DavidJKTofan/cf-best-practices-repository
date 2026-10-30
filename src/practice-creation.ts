import { requireAccessIdentity, type RuntimeEnv } from './access';
import { HttpError, json, log } from './http';
import { createPractice } from './modules/catalog/creation';
import { purgeReadCache } from './platform/cache';
import { validatePractice } from './practice-validation';
import { readJsonBody } from './request-body';

export { createPractice } from './modules/catalog/creation';

export function requireIdempotencyKey(request: Request): string {
	const key = request.headers.get('Idempotency-Key') ?? '';
	if (!/^[A-Za-z0-9_-]{16,128}$/.test(key))
		throw new HttpError(400, 'Idempotency-Key must be 16–128 letters, digits, hyphens, or underscores');
	return key;
}

export async function handleCreatePractice(request: Request, env: RuntimeEnv, ctx: ExecutionContext, url: URL): Promise<Response> {
	if (request.method !== 'POST') throw new HttpError(405, 'Method not allowed', { Allow: 'POST' });
	const identity = await requireAccessIdentity(request, env, url);
	const key = requireIdempotencyKey(request);
	const practice = validatePractice(await readJsonBody(request));
	let id: number;
	try {
		id = await createPractice(env.DB, practice, identity.subject, key);
	} catch (err) {
		const message = String(err);
		if (message.includes('FOREIGN KEY constraint failed')) throw new HttpError(400, 'Unknown category_id or feature_id');
		if (message.includes('CHECK constraint failed')) throw new HttpError(400, 'One or more fields have an invalid value');
		throw err;
	}
	log('log', 'practice saved', { id, title: practice.title, by: identity.email });
	// Replays purge too, recovering from a committed write whose response/purge was lost.
	// Purging cannot invalidate browser caches and failure does not undo the committed write.
	await purgeReadCache(ctx);
	return json({ success: true, message: 'Practice created successfully', id }, { status: 201, headers: { 'Cache-Control': 'no-store' } });
}
