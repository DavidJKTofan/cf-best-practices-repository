import { requireAccessIdentity, type RuntimeEnv } from '../../access';
import { HttpError } from '../../http';

export type EditorialRole = 'editor' | 'reviewer' | 'publisher';
export async function sha256(value: string): Promise<string> {
	const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
	return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
export async function requireEditorialActor(request: Request, env: RuntimeEnv, role?: EditorialRole) {
	const identity = await requireAccessIdentity(request, env, new URL(request.url));
	const actor = await sha256(identity.subject);
	const grants = await env.DB.withSession('first-primary')
		.prepare('SELECT role FROM EditorialRoles WHERE actor_hash = ?')
		.bind(actor)
		.all<{ role: EditorialRole }>();
	const roles = grants.results.map((grant) => grant.role);
	if (!roles.length || (role && !roles.includes(role))) throw new HttpError(403, 'Editorial role required');
	return { actor, roles };
}
