import { handle } from '@astrojs/cloudflare/handler';
import { PublicReads as DomainReads } from './public-reads';
import { contentError } from '../public-content';
import { finalizeDocument } from '../platform/content-response';
import { documentPath, isCatalogListing, markdownPath } from '../modules/catalog/document-state';
import { prefersMarkdown } from '../content-negotiation';

export class PublicReads extends DomainReads {
	override async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const path = url.pathname;
		const html = !path.endsWith('.md') && !prefersMarkdown(request.headers.get('Accept'));
		if (!html || !(path === '/' || isCatalogListing(path) || /^\/practices\/[1-9]\d*$/.test(path))) return super.fetch(request);
		try {
			return finalizeDocument(await handle(request, this.env, this.ctx), documentPath(url), markdownPath(url));
		} catch (err) {
			console.error(err);
			return contentError(503);
		}
	}
}
