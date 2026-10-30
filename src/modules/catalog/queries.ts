import { log, parseId } from '../../http';
import { PRACTICES_SQL, type Practice } from '../../practice-data';
import { ENUM_FILTERS } from './filters';

// Callers supply their first-primary session; queries do not own HTTP or cache policy.
export function getPractice(db: D1DatabaseSession, id: number): Promise<Practice | null> {
	return db.prepare(`${PRACTICES_SQL} WHERE bp.practice_id = ?`).bind(id).first<Practice>();
}

export async function listAllPractices(db: D1DatabaseSession): Promise<Practice[]> {
	return (await db.prepare(`${PRACTICES_SQL} ORDER BY bp.domain, category_name, bp.title`).all<Practice>()).results;
}

export async function listPractices(db: D1DatabaseSession, url: URL): Promise<Practice[]> {
	const params = url.searchParams;
	const conditions: string[] = [];
	const bindings: (string | number)[] = [];
	const search = params.get('search');
	if (search) {
		const columns = ['bp.title', 'bp.description', 'bp.expression', 'bp.expressions_configuration_details', 'bp.prerequisites', 'bp.notes'];
		// Keep literal, per-field matching and SQLite's ASCII-only case folding,
		// without LIKE's 50-byte pattern limit or a second, shorter search bound.
		conditions.push(`(${columns.map((column) => `instr(lower(${column}), lower(?)) > 0`).join(' OR ')})`);
		bindings.push(...columns.map(() => search));
	}
	for (const [param, column] of [
		['categoryId', 'bp.category_id'],
		['featureId', 'bp.feature_id'],
	]) {
		const id = parseId(params.get(param));
		if (id) {
			conditions.push(`${column} = ?`);
			bindings.push(id);
		}
	}
	for (const [param, column, allowed] of ENUM_FILTERS) {
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
		.all<Practice>();
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
