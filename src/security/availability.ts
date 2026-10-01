const LOCAL_DEV_REGION = 'dev1';

export function scanningEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
	return env.SCANNER_ENABLED === 'true' || env.VERCEL_REGION === LOCAL_DEV_REGION;
}
