import { env } from 'cloudflare:workers';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { requireAccessIdentity } from '../src/access';

let privateKey;
let jwk;
beforeAll(async () => {
	const pair = await generateKeyPair('RS256', { modulusLength: 2048 });
	privateKey = pair.privateKey;
	jwk = { ...(await exportJWK(pair.publicKey)), kid: 'test-access-key', alg: 'RS256' };
});
afterEach(() => vi.restoreAllMocks());

async function token(issuer, { aud = 'test-audience', exp = Math.floor(Date.now() / 1000) + 300, sub = 'user-123', ...claims } = {}) {
	return new SignJWT({ email: 'writer@example.com', ...claims })
		.setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
		.setIssuer(issuer)
		.setAudience(aud)
		.setSubject(sub)
		.setIssuedAt()
		.setExpirationTime(exp)
		.sign(privateKey);
}

function verify(jwt, issuer) {
	const request = new Request('https://example.com/dashboard/api/practices', { headers: { 'Cf-Access-Jwt-Assertion': jwt } });
	return requireAccessIdentity(
		request,
		{ ...env, ACCESS_TEAM_DOMAIN: issuer, ACCESS_AUD: 'test-audience', ALLOW_LOCAL_WRITES: 'false' },
		new URL(request.url),
	);
}

describe('Access JWT verification and public key cache', () => {
	it('validates signed identities and reuses an issuer-scoped public key cache', async () => {
		const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ keys: [jwk] }));
		const issuer = 'https://cache-test.cloudflareaccess.com';
		const jwt = await token(issuer);
		expect(await verify(jwt, issuer)).toMatchObject({ email: 'writer@example.com' });
		expect(await verify(jwt, issuer)).toMatchObject({ subject: JSON.stringify([issuer, 'user', 'user-123']) });
		expect(fetch).toHaveBeenCalledOnce();
		const otherIssuer = 'https://other-team.cloudflareaccess.com';
		await verify(await token(otherIssuer), otherIssuer);
		expect(fetch).toHaveBeenCalledTimes(2);
	});

	it('rejects wrong audience, wrong issuer, expired tokens, and missing stable identity', async () => {
		vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ keys: [jwk] }));
		const issuer = 'https://validation-test.cloudflareaccess.com';
		for (const jwt of [
			await token(issuer, { aud: 'wrong' }),
			await token('https://wrong.example.com'),
			await token(issuer, { exp: 1 }),
			await token(issuer, { sub: '' }),
		]) {
			await expect(verify(jwt, issuer)).rejects.toMatchObject({ status: 403 });
		}
	});

	it('preserves Access service-token support using its signed common_name', async () => {
		vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ keys: [jwk] }));
		const issuer = 'https://service-test.cloudflareaccess.com';
		const jwt = await token(issuer, { sub: '', common_name: 'service-id.access' });
		expect(await verify(jwt, issuer)).toMatchObject({ subject: JSON.stringify([issuer, 'service', 'service-id.access']) });
	});
});
