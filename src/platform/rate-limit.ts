import { HttpError, log } from '../http';

export async function enforceRateLimit(env: Env, key: string): Promise<void> {
	if (!env.MY_RATE_LIMITER) return;
	try {
		const { success } = await env.MY_RATE_LIMITER.limit({ key });
		if (!success) {
			log('warn', 'rate limited', { key });
			throw new HttpError(429, 'Rate limit exceeded. Please try again later.', { 'Retry-After': '60' });
		}
	} catch (err) {
		if (err instanceof HttpError) throw err;
		console.error(err); // Soft guard: fail open on limiter outages, not on an explicit rejection.
	}
}
