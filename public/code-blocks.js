// Shared, progressively enhanced code controls for catalog details and canonical pages.
export function enhanceCodeBlock(block) {
	if (block.querySelector('.code-actions')) return;
	const pre = block.querySelector('pre');
	const code = pre?.querySelector('code');
	if (!code) return;

	const expression = block.dataset.copyKind === 'expression';
	const label = expression ? 'expression' : 'configuration';
	const actions = document.createElement('div');
	actions.className = 'code-actions';
	const wrap = document.createElement('button');
	wrap.type = 'button';
	wrap.className = 'btn btn-small wrap-btn';
	wrap.textContent = 'Wrap lines';
	wrap.setAttribute('aria-pressed', String(block.classList.contains('is-wrapped')));
	wrap.addEventListener('click', () => {
		wrap.setAttribute('aria-pressed', String(block.classList.toggle('is-wrapped')));
	});
	const copy = document.createElement('button');
	copy.type = 'button';
	copy.className = 'btn btn-small copy-btn';
	const copyLabel = `Copy ${label}`;
	copy.textContent = copyLabel;
	const feedback = document.createElement('p');
	feedback.className = 'copy-feedback visually-hidden';
	feedback.setAttribute('role', 'status');
	feedback.setAttribute('aria-live', 'polite');
	feedback.setAttribute('aria-atomic', 'true');
	let resetTimer;
	copy.addEventListener('click', async () => {
		clearTimeout(resetTimer);
		copy.disabled = true;
		feedback.textContent = '';
		try {
			// textContent preserves the original bytes, including quotes/newlines, without <mark> tags.
			await navigator.clipboard.writeText(code.textContent);
			copy.textContent = 'Copied';
			feedback.className = 'copy-feedback visually-hidden';
			feedback.textContent = `${expression ? 'Expression' : 'Configuration'} copied.`;
		} catch {
			copy.textContent = 'Copy failed';
			feedback.className = 'copy-feedback';
			feedback.textContent = 'Copy failed. Select the code and use your device’s copy command.';
			pre.focus({ preventScroll: true });
			const selection = window.getSelection();
			const range = document.createRange();
			range.selectNodeContents(code);
			selection?.removeAllRanges();
			selection?.addRange(range);
		} finally {
			copy.disabled = false;
			resetTimer = setTimeout(() => {
				copy.textContent = copyLabel;
			}, 1800);
		}
	});
	actions.append(wrap, copy);
	block.prepend(actions);
	block.append(feedback);
}

export function createCodeBlock(text, kind, content = document.createTextNode(text)) {
	const block = document.createElement('div');
	block.className = 'code-block is-wrapped';
	block.dataset.copyKind = kind;
	const pre = document.createElement('pre');
	pre.tabIndex = 0;
	pre.setAttribute('aria-label', kind === 'expression' ? 'Example expression' : 'Configuration guidance');
	const code = document.createElement('code');
	code.append(content);
	pre.append(code);
	block.append(pre);
	enhanceCodeBlock(block);
	return block;
}

document.querySelectorAll('.code-block').forEach(enhanceCodeBlock);
