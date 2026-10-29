import { log } from './http';

const RETRYABLE_D1_ERRORS = [
	'Network connection lost',
	'storage caused object to be reset',
	'reset because its code was updated',
	'Replica disconnected from primary',
	'Cannot resolve D1 DB due to transient issue on remote node',
];

// Only use for application-idempotent operations. D1 already retries eligible read-only queries.
export async function withWriteRetry<T>(operation: () => Promise<T>, { attempts = 4, baseDelayMs = 100 } = {}): Promise<T> {
	for (let attempt = 1; ; attempt++) {
		try {
			return await operation();
		} catch (err) {
			if (!RETRYABLE_D1_ERRORS.some((message) => String(err).includes(message)) || attempt >= attempts) throw err;
			const delay = Math.random() * baseDelayMs * 2 ** attempt;
			log('warn', 'retrying d1 write', { attempt, delay_ms: Math.round(delay), error: String(err) });
			await new Promise<void>((resolve) => setTimeout(resolve, delay));
		}
	}
}
