export type MxAnswer = {
	readonly exchange: string;
	readonly priority: number;
};

export type RecordClient = {
	resolve4(host: string): Promise<string[]>;
	resolve6(host: string): Promise<string[]>;
	resolveTxt(host: string): Promise<string[][]>;
	resolveMx(host: string): Promise<MxAnswer[]>;
	resolveCaa(host: string): Promise<readonly object[]>;
};

export class DnsFailure extends Error {}

export class LookupBudgetExceeded extends Error {}

export type Lookup = {
	a(name: string): Promise<string[]>;
	aaaa(name: string): Promise<string[]>;
	txt(name: string): Promise<string[]>;
	mx(name: string): Promise<MxAnswer[]>;
	caa(name: string): Promise<readonly object[]>;
	readonly used: () => number;
};

const NO_ANSWER = new Set(['ENOTFOUND', 'ENODATA']);

function deadline(signal: AbortSignal | undefined): Promise<never> | undefined {
	if (signal === undefined) {
		return undefined;
	}
	return new Promise<never>((_, reject) => {
		const abort = (): void => reject(new DnsFailure('deadline'));
		if (signal.aborted) {
			abort();
		} else {
			signal.addEventListener('abort', abort, { once: true });
		}
	});
}

export function createLookup(client: RecordClient, limit: number, signal?: AbortSignal): Lookup {
	let used = 0;
	const stop = deadline(signal);
	stop?.catch(() => undefined);
	const ask = async <T>(run: () => Promise<T[]>): Promise<T[]> => {
		if (used >= limit) {
			throw new LookupBudgetExceeded(`more than ${limit} DNS queries`);
		}
		used++;
		try {
			return await (stop === undefined ? run() : Promise.race([run(), stop]));
		} catch (error) {
			if (error instanceof DnsFailure) {
				throw error;
			}
			const code = (error as NodeJS.ErrnoException).code ?? '';
			if (NO_ANSWER.has(code)) {
				return [];
			}
			throw new DnsFailure(code || 'DNS query failed');
		}
	};
	return {
		a: (name) => ask(() => client.resolve4(name)),
		aaaa: (name) => ask(() => client.resolve6(name)),
		txt: async (name) => (await ask(() => client.resolveTxt(name))).map((chunks) => chunks.join('')),
		mx: (name) => ask(() => client.resolveMx(name)),
		caa: (name) => ask(async () => [...(await client.resolveCaa(name))]),
		used: () => used
	};
}
