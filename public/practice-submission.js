// Keep only an opaque operation key, never form contents or credentials, in tab-local storage.
export function createSubmission(storage) {
	const name = 'practice-creation-key-v1';
	let key;
	try {
		key = storage?.getItem(name);
	} catch (err) {
		console.error(err);
	}
	return {
		pending() {
			return Boolean(key);
		},
		key() {
			if (!key) {
				key = crypto.randomUUID();
				try {
					storage?.setItem(name, key);
				} catch (err) {
					console.error(err);
				}
			}
			return key;
		},
		complete() {
			key = undefined;
			try {
				storage?.removeItem(name);
			} catch (err) {
				console.error(err);
			}
		},
	};
}
