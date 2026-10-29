import { describe, expect, it, vi } from 'vitest';
import { MAX_BODY_BYTES, readJsonBody } from '../src/request-body';

function request(body, headers = {}) {
	return new Request('https://example.com/dashboard/api/practices', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...headers },
		body,
	});
}

describe('bounded JSON reading', () => {
	it.each([{}, { 'Content-Length': '1' }])('counts bytes without trusting Content-Length: %j', async (headers) => {
		const text = JSON.stringify({ text: '🦊'.repeat(17_000) });
		expect(text.length).toBeLessThan(MAX_BODY_BYTES);
		await expect(readJsonBody(request(text, headers))).rejects.toMatchObject({ status: 413 });
	});

	it('cancels as soon as the limit is exceeded without consuming the remainder', async () => {
		let reads = 0;
		const cancel = vi.fn();
		const body = new ReadableStream(
			{
				pull(controller) {
					reads++;
					controller.enqueue(new Uint8Array(16 * 1024));
				},
				cancel,
			},
			{ highWaterMark: 0 },
		);
		await expect(readJsonBody(request(body))).rejects.toMatchObject({ status: 413 });
		expect(reads).toBe(5);
		expect(cancel).toHaveBeenCalledOnce();
	});

	it('rejects a declared oversize before reading', async () => {
		const pull = vi.fn();
		const cancel = vi.fn();
		const body = new ReadableStream({ pull, cancel }, { highWaterMark: 0 });
		await expect(readJsonBody(request(body, { 'Content-Length': String(MAX_BODY_BYTES + 1) }))).rejects.toMatchObject({ status: 413 });
		expect(pull).not.toHaveBeenCalled();
		expect(cancel).toHaveBeenCalledOnce();
	});

	it('accepts exactly 64 KiB and decodes split multibyte sequences', async () => {
		const text = JSON.stringify('x'.repeat(MAX_BODY_BYTES - 2));
		expect(await readJsonBody(request(text))).toHaveLength(MAX_BODY_BYTES - 2);
		const bytes = new TextEncoder().encode('"🦊"');
		const body = new ReadableStream({
			start(controller) {
				for (const byte of bytes) controller.enqueue(Uint8Array.of(byte));
				controller.close();
			},
		});
		expect(await readJsonBody(request(body))).toBe('🦊');
	});

	it.each(['', '{bad', Uint8Array.of(34, 255, 34)])('rejects invalid JSON/UTF-8: %j', async (body) => {
		await expect(readJsonBody(request(body))).rejects.toMatchObject({ status: 400 });
	});

	it('requires the exact JSON media type but accepts its parameters', async () => {
		await expect(readJsonBody(request('{}', { 'Content-Type': 'application/jsonp' }))).rejects.toMatchObject({ status: 415 });
		expect(await readJsonBody(request('{}', { 'Content-Type': 'Application/JSON; charset=utf-8' }))).toEqual({});
	});
});
