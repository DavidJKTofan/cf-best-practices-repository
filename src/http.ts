export class HttpError extends Error {
	constructor(
		public readonly status: number,
		message: string,
		public readonly headers: Record<string, string> = {},
	) {
		super(message);
	}
}

const API_HEADERS = {
	'X-Content-Type-Options': 'nosniff',
	'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'X-Robots-Tag': 'noindex',
	'Content-Signal': 'search=yes, ai-input=yes, ai-train=no',
};

export function json(data: unknown, { status = 200, headers = {} }: { status?: number; headers?: Record<string, string> } = {}): Response {
	return Response.json(data, { status, headers: { ...API_HEADERS, ...headers } });
}

export function log(level: 'log' | 'warn' | 'error', message: string, fields: Record<string, unknown> = {}): void {
	console[level](JSON.stringify({ message, ...fields }));
}

export function parseId(value: unknown): number | null {
	if (typeof value !== 'string' && typeof value !== 'number') return null;
	const id = Number(value);
	return Number.isInteger(id) && id > 0 && id <= 2147483647 ? id : null;
}
