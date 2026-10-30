import { log } from '../http';

export const CONTENT_CACHE_TAG = 'practices';
export const TAXONOMY_CACHE_TAG = 'taxonomy';
export const EDGE_CACHE_CONTROL = 'public, max-age=3600, stale-while-revalidate=86400';
export const CONTENT_CACHE_CONTROL = 'public, max-age=60, stale-while-revalidate=600';
export const TAXONOMY_CACHE_CONTROL = 'public, max-age=300, stale-while-revalidate=3600';

// Called only by PublicReads.purgePractices(): ctx.cache is scoped to that entrypoint.
export async function purgePractices(ctx: ExecutionContext) {
	if (!ctx.cache) return { success: true, errors: [] }; // Not emulated by wrangler dev.
	return ctx.cache.purge({ tags: [CONTENT_CACHE_TAG] });
}

export async function purgeReadCache(ctx: ExecutionContext): Promise<void> {
	try {
		const result = await ctx.exports.PublicReads.purgePractices();
		if (!result?.success) log('error', 'cache purge failed', { errors: result?.errors });
	} catch (err) {
		console.error(err);
	}
}
