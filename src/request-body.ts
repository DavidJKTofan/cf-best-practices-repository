import { HttpError } from './http';

export const MAX_BODY_BYTES = 64 * 1024;

export async function readJsonBody(request: Request): Promise<unknown> {
	// An exact JSON media type forces cross-site callers to preflight (no form-based CSRF).
	const mediaType = (request.headers.get('Content-Type') ?? '').split(';')[0].trim().toLowerCase();
	if (mediaType !== 'application/json') throw new HttpError(415, 'Content-Type must be application/json');
	if (Number(request.headers.get('Content-Length')) > MAX_BODY_BYTES) {
		if (request.body) void request.body.cancel().catch((err: unknown) => console.error(err));
		throw new HttpError(413, 'Request body too large');
	}

	const chunks: Uint8Array[] = [];
	let size = 0;
	if (request.body) {
		const reader = request.body.getReader();
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				size += value.byteLength;
				if (size > MAX_BODY_BYTES) {
					// Do not wait for an untrusted producer's cancellation callback to complete.
					void reader.cancel().catch((err: unknown) => console.error(err));
					throw new HttpError(413, 'Request body too large');
				}
				chunks.push(value);
			}
		} finally {
			reader.releaseLock();
		}
	}
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	try {
		return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes));
	} catch {
		throw new HttpError(400, 'Invalid JSON in request body');
	}
}
