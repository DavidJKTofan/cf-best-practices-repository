import type { RequestScope } from './request-scope';
import { HttpError, json, parseId } from '../http';
import { readJsonBody } from '../request-body';
import { requireIdempotencyKey } from '../practice-creation';
import { purgeReadCache } from '../platform/cache';
import { requireEditorialActor, type EditorialRole } from '../modules/editorial/authorization';
import { getDraft, listDrafts, publicationHistory } from '../modules/editorial/queries';
import { validateCommand, type EditorialCommand } from '../modules/editorial/validation';
import { mutateEditorial } from '../modules/editorial/mutations';
import { previewDraft } from '../modules/editorial/preview';

export async function handleCatalogEditorial({ request, env, ctx, url }: RequestScope): Promise<Response> {
	// These routes never traverse PublicReads, add CORS, or accept form writes.
	const match = /^\/dashboard\/api\/catalog(?:\/([1-9]\d*)\/(draft|preview|submit|review|publish|rebase|history))?$/.exec(url.pathname);
	if (!match) throw new HttpError(404, 'Editorial route not found');
	const id = match[1] ? parseId(match[1]) : null;
	if (match[1] && !id) throw new HttpError(404, 'Editorial route not found');
	const action = match[2];
	const read = request.method === 'GET' || request.method === 'HEAD';
	const allowed = !action
		? ['GET', 'HEAD', 'POST']
		: action === 'draft'
			? ['GET', 'HEAD', 'PUT']
			: action === 'preview' || action === 'history'
				? ['GET', 'HEAD']
				: ['POST'];
	if (!allowed.includes(request.method)) throw new HttpError(405, 'Method not allowed', { Allow: allowed.join(', ') });
	if (
		!read &&
		((request.headers.has('Origin') && request.headers.get('Origin') !== url.origin) ||
			request.headers.get('Sec-Fetch-Site') === 'cross-site')
	)
		throw new HttpError(403, 'Cross-origin editorial writes are forbidden');
	const command: EditorialCommand = !action ? 'create' : action === 'draft' ? 'save' : (action as EditorialCommand);
	const role: EditorialRole | undefined = read
		? undefined
		: command === 'review'
			? 'reviewer'
			: command === 'publish'
				? 'publisher'
				: 'editor';
	const { actor, roles } = await requireEditorialActor(request, env, role);
	let response: Response;
	if (read) {
		const db = env.DB.withSession('first-primary');
		response =
			action === 'history'
				? json({ success: true, ...(await publicationHistory(db, id!, url)) })
				: action === 'preview'
					? previewDraft(await getDraft(db, id!), url.searchParams.get('format') === 'markdown')
					: json({ success: true, roles, data: action ? await getDraft(db, id!) : await listDrafts(db, url) });
	} else {
		const key = requireIdempotencyKey(request);
		const data = validateCommand(command, await readJsonBody(request));
		const result = await mutateEditorial(env.DB, command, id, data, actor, key);
		if (result.purge) await purgeReadCache(ctx);
		response = json({ success: true, data: result }, { status: command === 'create' ? 201 : 200 });
	}
	response.headers.set('Cache-Control', 'private, no-store');
	response.headers.set('Content-Signal', 'search=no, ai-input=no, ai-train=no');
	response.headers.set('X-Robots-Tag', 'noindex, nofollow');
	return request.method === 'HEAD' ? new Response(null, response) : response;
}
