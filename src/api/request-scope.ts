import type { RuntimeEnv } from '../access';

// Only routing configuration is shared. Raw requests and platform contexts stay request-scoped.
// Do not use Hono's loosely typed executionCtx.exports for loopback fetch or purge RPC.
export interface RequestScope {
	request: Request;
	env: RuntimeEnv;
	ctx: ExecutionContext;
	url: URL;
}

export type RouterEnv = { Bindings: RuntimeEnv };
