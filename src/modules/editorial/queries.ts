import { validateContent } from '../../content/validation';
import { validateLifecycle } from '../../content/lifecycle';
import { HttpError } from '../../http';

export async function getDraft(db: D1DatabaseSession, id: number) {
	const row = await db
		.prepare(
			`SELECT d.*, s.status, s.base_revision_id FROM CatalogDrafts d
		JOIN EditorialDraftState s USING (practice_id) WHERE d.practice_id = ?`,
		)
		.bind(id)
		.first<{
			practice_id: number;
			version: number;
			content_json: string;
			lifecycle_json: string;
			updated_at: string;
			status: string;
			base_revision_id: number | null;
		}>();
	if (!row) throw new HttpError(404, 'Editorial draft not found');
	return {
		practiceId: id,
		version: row.version,
		status: row.status,
		baseRevisionId: row.base_revision_id,
		updatedAt: row.updated_at,
		content: validateContent(JSON.parse(row.content_json)),
		lifecycle: validateLifecycle(JSON.parse(row.lifecycle_json)),
	};
}
export async function listDrafts(db: D1DatabaseSession, url: URL) {
	const page = Math.min(10000, Math.max(1, Number(url.searchParams.get('page')) || 1));
	return (
		await db
			.prepare(
				`SELECT d.practice_id AS practiceId, d.version, s.status, d.updated_at AS updatedAt,
		json_extract(d.content_json, '$.title') AS title, json_extract(d.content_json, '$.type') AS type
		FROM CatalogDrafts d JOIN EditorialDraftState s USING (practice_id) ORDER BY d.practice_id DESC LIMIT 20 OFFSET ?`,
			)
			.bind((Math.floor(page) - 1) * 20)
			.all()
	).results;
}

export async function publicationHistory(db: D1DatabaseSession, id: number, url: URL) {
	const input = url.searchParams.get('before');
	const before = input === null ? null : Number(input);
	if (before !== null && (!Number.isSafeInteger(before) || before < 1)) throw new HttpError(400, 'Invalid history cursor');
	const rows = (
		await db
			.prepare(
				`SELECT p.revision_id AS revisionId, p.published_at AS publishedAt, r.title
		FROM CatalogPublications p JOIN CatalogRevisions r USING (revision_id) WHERE p.practice_id = ?
		AND (? IS NULL OR p.revision_id < ?) ORDER BY p.revision_id DESC LIMIT 51`,
			)
			.bind(id, before, before)
			.all<{ revisionId: number; publishedAt: string; title: string }>()
	).results;
	return { data: rows.slice(0, 50), nextBeforeRevisionId: rows.length > 50 ? rows[49].revisionId : null };
}
