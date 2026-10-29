import { requireAccessIdentity, type RuntimeEnv } from './access';
import { withWriteRetry } from './d1-retry';
import { HttpError, json, log } from './http';
import { validatePractice, type PracticeInput } from './practice-validation';
import { readJsonBody } from './request-body';

async function sha256(value: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function requireIdempotencyKey(request: Request): string {
	const key = request.headers.get('Idempotency-Key') ?? '';
	if (!/^[A-Za-z0-9_-]{16,128}$/.test(key))
		throw new HttpError(400, 'Idempotency-Key must be 16–128 letters, digits, hyphens, or underscores');
	return key;
}

interface CreationReceipt {
	practice_id: number;
	payload_hash: string;
}

export async function createPractice(db: D1Database, practice: PracticeInput, subject: string, key: string): Promise<number> {
	const operationKey = await sha256(JSON.stringify(['create-practice:v1', subject, key]));
	const payloadHash = await sha256(JSON.stringify(practice));
	const columns = Object.keys(practice);
	// D1 batches are sequential SQL transactions. The receipt and insert commit together, or neither does.
	// On replay both INSERTs are skipped, leaving the original receipt untouched.
	const statements = [
		db
			.prepare(
				`INSERT INTO BestPractices (${columns.join(', ')})
			SELECT ${columns.map(() => '?').join(', ')}
			WHERE NOT EXISTS (SELECT 1 FROM PracticeCreations WHERE operation_key = ?)`,
			)
			.bind(...Object.values(practice), operationKey),
		db
			.prepare(
				`INSERT INTO PracticeCreations (operation_key, payload_hash, practice_id)
			SELECT ?, ?, last_insert_rowid()
			WHERE NOT EXISTS (SELECT 1 FROM PracticeCreations WHERE operation_key = ?)`,
			)
			.bind(operationKey, payloadHash, operationKey),
		db.prepare('SELECT practice_id, payload_hash FROM PracticeCreations WHERE operation_key = ?').bind(operationKey),
	];
	const results = await withWriteRetry(() => db.batch<CreationReceipt>(statements));
	const receipt = results[2].results[0];
	if (!receipt) throw new Error('Missing practice creation receipt');
	if (receipt.payload_hash !== payloadHash) throw new HttpError(409, 'Idempotency-Key was already used with different practice data');
	return receipt.practice_id;
}

async function purgeReadCache(ctx: ExecutionContext): Promise<void> {
	try {
		const result = await ctx.exports.PublicReads.purgePractices();
		if (!result?.success) log('error', 'cache purge failed', { errors: result?.errors });
	} catch (err) {
		console.error(err);
	}
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
