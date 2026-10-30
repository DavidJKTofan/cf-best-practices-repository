import { validateContent } from '../../content/validation';
import { validateLifecycle } from '../../content/lifecycle';
import { HttpError } from '../../http';

export type EditorialCommand = 'create' | 'save' | 'submit' | 'review' | 'publish' | 'rebase';
export function validateCommand(command: EditorialCommand, input: unknown) {
	if (!input || typeof input !== 'object' || Array.isArray(input)) throw new HttpError(400, 'Invalid editorial command');
	const v = input as Record<string, unknown>;
	const keys =
		command === 'create'
			? ['content', 'lifecycle']
			: command === 'save'
				? ['expectedVersion', 'content', 'lifecycle']
				: command === 'review'
					? ['expectedVersion', 'decision']
					: command === 'rebase'
						? ['expectedVersion', 'expectedPublishedRevisionId']
						: ['expectedVersion'];
	if (Object.keys(v).sort().join(',') !== keys.sort().join(',')) throw new HttpError(400, 'Invalid editorial command fields');
	const expectedVersion = command === 'create' ? 0 : v.expectedVersion;
	if (typeof expectedVersion !== 'number' || !Number.isSafeInteger(expectedVersion) || expectedVersion < 0 || expectedVersion >= 2147483647)
		throw new HttpError(400, 'Invalid expectedVersion');
	if (command === 'review' && v.decision !== 'approve' && v.decision !== 'request-changes')
		throw new HttpError(400, 'Invalid review decision');
	if (
		command === 'rebase' &&
		v.expectedPublishedRevisionId !== null &&
		(typeof v.expectedPublishedRevisionId !== 'number' ||
			!Number.isSafeInteger(v.expectedPublishedRevisionId) ||
			v.expectedPublishedRevisionId < 1)
	)
		throw new HttpError(400, 'Invalid expectedPublishedRevisionId');
	return {
		expectedVersion,
		content: command === 'create' || command === 'save' ? validateContent(v.content) : null,
		lifecycle: command === 'create' || command === 'save' ? validateLifecycle(v.lifecycle) : null,
		decision: command === 'review' ? (v.decision as 'approve' | 'request-changes') : null,
		expectedPublishedRevisionId: command === 'rebase' ? (v.expectedPublishedRevisionId as number | null) : null,
	};
}
export type ValidatedCommand = ReturnType<typeof validateCommand>;
