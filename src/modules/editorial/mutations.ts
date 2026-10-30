import { withWriteRetry } from '../../d1-retry';
import { HttpError } from '../../http';
import { sha256 } from './authorization';
import { getDraft } from './queries';
import type { EditorialCommand, ValidatedCommand } from './validation';

interface Receipt {
	payload_hash: string;
	practice_id: number;
	version: number;
	revision_id: number | null;
	purge: number;
}
function result(receipt: Receipt) {
	return { practiceId: receipt.practice_id, version: receipt.version, revisionId: receipt.revision_id, purge: receipt.purge === 1 };
}

export async function mutateEditorial(
	db: D1Database,
	command: EditorialCommand,
	id: number | null,
	data: ValidatedCommand,
	actor: string,
	key: string,
) {
	// All commands share one actor/key namespace; endpoint and target are hashed data.
	const operationKey = await sha256(JSON.stringify(['catalog-editorial:v1', actor, key]));
	const payloadHash = await sha256(JSON.stringify([command, id, data]));
	const session = db.withSession('first-primary');
	const existing = await session.prepare('SELECT * FROM EditorialMutations WHERE operation_key = ?').bind(operationKey).first<Receipt>();
	if (existing) {
		if (existing.payload_hash !== payloadHash) throw new HttpError(409, 'Idempotency-Key already used with different editorial data');
		return result(existing);
	}
	if (command === 'submit' || command === 'publish') {
		const draft = await getDraft(session, id!);
		const c = draft.content;
		const today = new Date().toISOString().slice(0, 10);
		if (
			c.evidence === 'unreviewed' ||
			!c.factVerifiedAt ||
			c.factVerifiedAt > today ||
			!c.modifiedAt ||
			c.modifiedAt > today ||
			!c.reviewDueAt ||
			c.reviewDueAt <= today ||
			c.factVerifiedAt > c.reviewDueAt
		)
			throw new HttpError(
				400,
				'Publication requires recorded public-source evidence, non-future fact/editorial dates and a future review date',
			);
	}
	const version = data.expectedVersion + 1;
	// Fresh attempt nonce on EVERY retry. A lost commit response then replays the
	// durable result without re-running writes, even inside the same Worker request.
	const receipt = await withWriteRetry(async () => {
		const attempt = crypto.randomUUID();
		const active = 'EXISTS (SELECT 1 FROM EditorialMutations WHERE operation_key = ? AND attempt = ?)';
		const statements: D1PreparedStatement[] = [];
		const add = (sql: string, ...args: (string | number | null)[]) => statements.push(db.prepare(sql).bind(...args, operationKey, attempt));
		let guard = '1';
		const guardArgs: (string | number | null)[] = [];
		if (command !== 'create') {
			guard = `SELECT e.legacy_practice_id IS NULL AND COALESCE(d.version, 0) = ?
				AND (d.practice_id IS NULL OR s.practice_id IS NOT NULL)`;
			guardArgs.push(data.expectedVersion);
			if (command === 'save') guard += ` AND (s.status IS NOT 'published' OR s.base_revision_id IS e.published_revision_id)`;
			if (command === 'submit') guard += ` AND s.status = 'draft'`;
			if (command === 'rebase') {
				guard += ` AND s.practice_id IS NOT NULL AND e.published_revision_id IS ?`;
				guardArgs.push(data.expectedPublishedRevisionId);
			}
			if (command === 'review' || command === 'publish') {
				guard += ` AND s.status = ? AND NOT EXISTS (SELECT 1 FROM EditorialAuthors a WHERE a.practice_id = e.practice_id AND a.actor_hash = ?)`;
				guardArgs.push(command === 'review' ? 'in-review' : 'approved', actor);
			}
			if (command === 'publish') {
				guard += ` AND s.base_revision_id IS e.published_revision_id
					AND EXISTS (SELECT 1 FROM EditorialRoles WHERE actor_hash = s.reviewer_hash AND role = 'reviewer')
					AND (json_extract(d.lifecycle_json, '$.state') != 'superseded' OR EXISTS (
						SELECT 1 FROM PublishedCatalog target WHERE target.practice_id = json_extract(d.lifecycle_json, '$.supersededBy')
						AND target.practice_id != e.practice_id AND json_extract(target.lifecycle_json, '$.state') = 'active'))`;
			}
			guard += ` FROM CatalogEntries e LEFT JOIN CatalogDrafts d USING (practice_id)
				LEFT JOIN EditorialDraftState s USING (practice_id) WHERE e.practice_id = ?`;
			guardArgs.push(id);
		}
		const requiredRole = command === 'review' ? 'reviewer' : command === 'publish' ? 'publisher' : 'editor';
		guard = `(${guard}) AND EXISTS (SELECT 1 FROM EditorialRoles WHERE actor_hash = ? AND role = ?)`;
		guardArgs.push(actor, requiredRole);
		statements.push(
			db
				.prepare(
					`INSERT INTO EditorialMutations (operation_key, payload_hash, attempt, guard, practice_id, version, purge)
			SELECT ?, ?, ?, COALESCE((${guard}), 0), ?, ?, ? WHERE true ON CONFLICT(operation_key) DO NOTHING`,
				)
				.bind(operationKey, payloadHash, attempt, ...guardArgs, id, version, command === 'publish' ? 1 : 0),
		);
		if (command === 'create') {
			add(`INSERT INTO CatalogEntries (legacy_practice_id) SELECT NULL WHERE ${active}`);
			add(`UPDATE EditorialMutations SET practice_id = last_insert_rowid() WHERE ${active} AND operation_key = '${operationKey}'`);
		}
		const target = `(SELECT practice_id FROM EditorialMutations WHERE operation_key = '${operationKey}')`;
		if (command === 'create' || command === 'save') {
			add(
				`INSERT INTO CatalogDrafts (practice_id, version, content_json, lifecycle_json)
				SELECT ${target}, ?, ?, ? WHERE ${active} ON CONFLICT(practice_id) DO UPDATE SET
				version = excluded.version, content_json = excluded.content_json, lifecycle_json = excluded.lifecycle_json, updated_at = CURRENT_TIMESTAMP`,
				version,
				JSON.stringify(data.content),
				JSON.stringify(data.lifecycle),
			);
			add(`INSERT INTO EditorialDraftState (practice_id, status, base_revision_id)
				SELECT practice_id, 'draft', published_revision_id FROM CatalogEntries WHERE practice_id = ${target} AND ${active}
				ON CONFLICT(practice_id) DO UPDATE SET status = 'draft', reviewer_hash = NULL,
				base_revision_id = CASE WHEN EditorialDraftState.status = 'published' THEN excluded.base_revision_id ELSE EditorialDraftState.base_revision_id END`);
			add(`INSERT INTO EditorialAuthors (practice_id, actor_hash) SELECT ${target}, ? WHERE ${active} ON CONFLICT DO NOTHING`, actor);
		} else {
			add(`UPDATE CatalogDrafts SET version = ?, updated_at = CURRENT_TIMESTAMP WHERE practice_id = ${target} AND ${active}`, version);
			if (command === 'submit') add(`UPDATE EditorialDraftState SET status = 'in-review' WHERE practice_id = ${target} AND ${active}`);
			if (command === 'rebase') {
				add(`UPDATE EditorialDraftState SET status = 'draft', reviewer_hash = NULL,
					base_revision_id = (SELECT published_revision_id FROM CatalogEntries WHERE practice_id = ${target}) WHERE practice_id = ${target} AND ${active}`);
				add(`INSERT INTO EditorialAuthors (practice_id, actor_hash) SELECT ${target}, ? WHERE ${active} ON CONFLICT DO NOTHING`, actor);
			}
			if (command === 'review') {
				add(
					`INSERT INTO EditorialReviews (operation_key, practice_id, draft_version, reviewer_hash, decision)
					SELECT '${operationKey}', ${target}, ?, ?, ? WHERE ${active}`,
					data.expectedVersion,
					actor,
					data.decision,
				);
				add(
					`UPDATE EditorialDraftState SET status = ?, reviewer_hash = ? WHERE practice_id = ${target} AND ${active}`,
					data.decision === 'approve' ? 'approved' : 'draft',
					data.decision === 'approve' ? actor : null,
				);
			}
			if (command === 'publish') {
				add(`INSERT INTO CatalogRevisions (practice_id, schema_version, content_type, title, summary, primary_family,
					applicability_json, body_json, evidence, maturity, modified_at, fact_verified_at, review_due_at, lifecycle_json)
					SELECT practice_id, 1, json_extract(content_json, '$.type'), json_extract(content_json, '$.title'), json_extract(content_json, '$.summary'),
					json_extract(content_json, '$.primaryFamily'), json_extract(content_json, '$.applicability'), json_extract(content_json, '$.body'),
					json_extract(content_json, '$.evidence'), json_extract(content_json, '$.maturity'), json_extract(content_json, '$.modifiedAt'),
					json_extract(content_json, '$.factVerifiedAt'), json_extract(content_json, '$.reviewDueAt'), lifecycle_json
					FROM CatalogDrafts WHERE practice_id = ${target} AND ${active}`);
				add(`UPDATE EditorialMutations SET revision_id = last_insert_rowid() WHERE operation_key = '${operationKey}' AND ${active}`);
				const revision = `(SELECT revision_id FROM EditorialMutations WHERE operation_key = '${operationKey}')`;
				for (const [kind, field] of [
					['family', 'families'],
					['product', 'products'],
					['outcome', 'outcomes'],
				])
					add(`INSERT INTO CatalogRevisionTaxa (revision_id, kind, slug) SELECT ${revision}, '${kind}', j.value
						FROM CatalogDrafts d, json_each(d.content_json, '$.${field}') j WHERE d.practice_id = ${target} AND ${active}`);
				add(`INSERT INTO CatalogRevisionSources (revision_id, position, url, title)
					SELECT ${revision}, CAST(j.key AS INTEGER), json_extract(j.value, '$.url'), json_extract(j.value, '$.title')
					FROM CatalogDrafts d, json_each(d.content_json, '$.sources') j WHERE d.practice_id = ${target} AND ${active}`);
				add(
					`INSERT INTO CatalogPublications (practice_id, revision_id, published_at) SELECT ${target}, ${revision}, CURRENT_TIMESTAMP WHERE ${active}`,
				);
				add(`UPDATE CatalogEntries SET published_revision_id = ${revision} WHERE practice_id = ${target} AND ${active}`);
				add(
					`UPDATE EditorialDraftState SET status = 'published', base_revision_id = ${revision} WHERE practice_id = ${target} AND ${active}`,
				);
			}
		}
		statements.push(db.prepare('SELECT * FROM EditorialMutations WHERE operation_key = ?').bind(operationKey));
		try {
			const results = await db.batch<Receipt>(statements);
			return results.at(-1)!.results[0];
		} catch (err) {
			if (String(err).includes('CHECK constraint failed: guard'))
				throw new HttpError(409, 'Draft version, workflow, authorship or publication base conflict');
			if (String(err).includes('FOREIGN KEY constraint failed')) throw new HttpError(400, 'Unknown catalog taxonomy');
			throw err;
		}
	});
	if (!receipt) throw new Error('Missing editorial mutation receipt');
	if (receipt.payload_hash !== payloadHash) throw new HttpError(409, 'Idempotency-Key already used with different editorial data');
	return result(receipt);
}
