import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSubmission } from '../public/practice-submission';

afterEach(() => vi.restoreAllMocks());

describe('dashboard retry keys', () => {
	it('retains the key for retries and reloads, and rotates only after confirmed success', () => {
		const values = new Map();
		const storage = {
			getItem: (key) => values.get(key),
			setItem: (key, value) => values.set(key, value),
			removeItem: (key) => values.delete(key),
		};
		const first = createSubmission(storage);
		const key = first.key();
		expect(first.key()).toBe(key);
		const reloaded = createSubmission(storage);
		expect(reloaded.key()).toBe(key);
		reloaded.complete();
		expect(reloaded.key()).not.toBe(key);
	});
	it('retains an in-memory key when browser storage is unavailable', () => {
		vi.spyOn(console, 'error').mockImplementation(() => {});
		const state = createSubmission({
			getItem() {
				throw new Error('Unavailable');
			},
			setItem() {
				throw new Error('Unavailable');
			},
		});
		expect(state.key()).toBe(state.key());
	});
});
