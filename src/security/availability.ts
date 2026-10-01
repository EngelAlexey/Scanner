const LOCAL_DEV_REGION = 'dev1';

export function isLocalDev(env: NodeJS.ProcessEnv = process.env): boolean {
	return env.VERCEL_REGION === LOCAL_DEV_REGION;
}

export function scanningEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
	return env.SCANNER_ENABLED === 'true' || isLocalDev(env);
}
