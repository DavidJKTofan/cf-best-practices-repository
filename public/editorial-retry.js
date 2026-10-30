// Persist only opaque retry metadata; private content remains in page memory.
export function createEditorialSubmission(storage) {
	const name = 'editorial-pending';
	let pending;
	try {
		const value = JSON.parse(storage?.getItem(name) ?? 'null');
		if (value && /^[a-f0-9]{64}$/.test(value.signature) && /^[A-Za-z0-9_-]{16,128}$/.test(value.key)) pending = value;
	} catch {
		/* Storage denial/corruption must not prevent in-page retries. */
	}
	return {
		async key(path, method, serialized, confirmNew) {
			const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${path}\n${method}\n${serialized}`));
			const signature = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
			if (pending && pending.signature !== signature && !confirmNew()) return null;
			if (pending?.signature !== signature) pending = { signature, key: crypto.randomUUID() };
			try {
				storage?.setItem(name, JSON.stringify(pending));
			} catch {
				/* In-memory protection still works. */
			}
			return pending.key;
		},
		complete() {
			pending = undefined;
			try {
				storage?.removeItem(name);
			} catch {
				/* Optional storage. */
			}
		},
	};
}
