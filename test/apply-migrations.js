import { applyD1Migrations } from 'cloudflare:test';
import { env } from 'cloudflare:workers';

// Setup files run outside isolated storage, so this applies once per test file
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
