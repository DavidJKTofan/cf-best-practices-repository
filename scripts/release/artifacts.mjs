import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
import { checkBoundaries } from '../verify-boundaries.mjs';

export async function files(directory) {
	const output = [];
	for (const entry of await readdir(directory, { withFileTypes: true })) {
		assert.ok(!entry.isSymbolicLink(), 'No symlinked public artifacts');
		const path = resolve(directory, entry.name);
		output.push(...(entry.isDirectory() ? await files(path) : [path]));
	}
	return output;
}

export async function checkPublicArtifacts(directory) {
	const sources = {};
	const publicFiles = await files(directory);
	assert.ok(publicFiles.length, 'Missing built public assets');
	for (const path of publicFiles) {
		const name = relative(resolve(directory), path);
		assert.ok(
			!/\.(?:map|ts|sql|astro)$|wrangler|worker-configuration|\.dev\.vars|pilots\.json/.test(name),
			'Server/config file in public assets',
		);
		const text = await readFile(path, 'utf8');
		assert.ok(
			!/create-practice:v1|PRIVATE KEY|ACCESS_AUD|PracticeCreations|PRIVATE_DRAFT_CANARY/.test(text),
			'Private/server bytes in public assets',
		);
		sources[`public/${name}`] = text;
	}
	assert.deepEqual(checkBoundaries(sources), [], 'Public artifact import boundary');
}
