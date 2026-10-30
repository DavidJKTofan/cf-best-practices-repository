import { withWriteRetry } from '../../d1-retry';
import { HttpError } from '../../http';
import type { PracticeInput } from '../../practice-validation';

async function sha256(value: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
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
