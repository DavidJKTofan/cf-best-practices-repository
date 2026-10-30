import { PRACTICES_SQL, type Practice } from '../../../src/practice-data';
import { parseId } from '../../../src/http';

export async function getPractice(db: D1Database, rawId: string | undefined): Promise<Practice | null> {
	const id = parseId(rawId);
	if (!id) return null;
	return db.withSession('first-primary').prepare(`${PRACTICES_SQL} WHERE bp.practice_id = ?`).bind(id).first<Practice>();
}

export async function listPreview(db: D1Database): Promise<Practice[]> {
	return (await db.withSession('first-primary').prepare(`${PRACTICES_SQL} ORDER BY bp.practice_id LIMIT 3`).all<Practice>()).results;
}
