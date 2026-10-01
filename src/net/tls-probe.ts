import { isIP } from 'node:net';
import tls from 'node:tls';
import type { SecureVersion } from 'node:tls';

export type VersionSupport = 'accepted' | 'rejected' | 'unknown';

export type PeerCertificate = {
	readonly dnsNames: readonly string[];
	readonly validFrom: string;
	readonly validTo: string;
	readonly issuer: string;
};

export type Handshake =
	| {
			readonly ok: true;
			readonly protocol: string;
			readonly authorizationError: string | null;
			readonly identityError: string | null;
			readonly certificate: PeerCertificate;
	  }
	| { readonly ok: false; readonly error: 'timeout' | 'refused' | 'failed' };

export type TlsProbe = {
	readonly handshake: Handshake;
	readonly tls10: VersionSupport;
	readonly tls11: VersionSupport;
};

export type TlsProbeOptions = {
	readonly port?: number;
	readonly timeoutMs?: number;
	readonly ca?: readonly string[];
	readonly signal?: AbortSignal;
};

const DEFAULT_PORT = 443;
const DEFAULT_TIMEOUT_MS = 5000;
const LEGACY_CIPHERS = 'DEFAULT:@SECLEVEL=0';
const LOCAL_ERRORS = new Set([
	'ERR_SSL_NO_PROTOCOLS_AVAILABLE',
	'ERR_SSL_NO_CIPHERS_AVAILABLE',
	'ERR_SSL_NO_SHARED_CIPHER',
	'ERR_TLS_INVALID_PROTOCOL_VERSION',
	'ERR_TLS_PROTOCOL_VERSION_CONFLICT'
]);

type Attempt =
	| { readonly ok: true; readonly socket: tls.TLSSocket }
	| { readonly ok: false; readonly code: string; readonly timedOut: boolean };

function errorCode(error: unknown): string {
	const candidate = error as { code?: unknown; message?: unknown } | null;
	if (typeof candidate?.code === 'string') {
		return candidate.code;
	}
	return typeof candidate?.message === 'string' ? candidate.message : String(error);
}

function attempt(host: string, address: string, options: TlsProbeOptions, versions: tls.ConnectionOptions): Promise<Attempt> {
	if (isIP(host) !== 0 || isIP(address) === 0) {
		throw new Error('the probe connects to an IP address and sends a host name as servername');
	}
	return new Promise((resolve) => {
		let settled = false;
		const finish = (result: Attempt, socket?: tls.TLSSocket): void => {
			if (settled) {
				socket?.destroy();
				return;
			}
			settled = true;
			clearTimeout(timer);
			options.signal?.removeEventListener('abort', onAbort);
			if (!result.ok) {
				socket?.destroy();
			}
			resolve(result);
		};
		const socket = tls.connect({
			host: address,
			port: options.port ?? DEFAULT_PORT,
			servername: host,
			rejectUnauthorized: false,
			ALPNProtocols: ['http/1.1'],
			...(options.ca === undefined ? {} : { ca: [...options.ca] }),
			...versions
		});
		const onAbort = (): void => finish({ ok: false, code: 'ABORTED', timedOut: true }, socket);
		const timer = setTimeout(() => finish({ ok: false, code: 'ETIMEDOUT', timedOut: true }, socket), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
		options.signal?.addEventListener('abort', onAbort, { once: true });
		socket.once('secureConnect', () => finish({ ok: true, socket }, socket));
		socket.once('error', (error) => finish({ ok: false, code: errorCode(error), timedOut: false }, socket));
		socket.once('close', () => finish({ ok: false, code: 'ECONNRESET', timedOut: false }, socket));
	});
}

function dnsNames(subjectAltName: string | undefined): string[] {
	return (subjectAltName ?? '')
		.split(',')
		.map((entry) => entry.trim())
		.filter((entry) => entry.startsWith('DNS:'))
		.map((entry) => entry.slice(4).toLowerCase());
}

function isoDate(value: string | undefined): string {
	const time = Date.parse(value ?? '');
	return Number.isNaN(time) ? '' : new Date(time).toISOString();
}

function describe(host: string, socket: tls.TLSSocket): Handshake {
	const certificate = socket.getPeerCertificate();
	const names = dnsNames(certificate.subjectaltname);
	const mismatch = names.length === 0 ? undefined : tls.checkServerIdentity(host, certificate);
	const identity = names.length === 0 ? 'NO_DNS_SUBJECT_ALT_NAME' : mismatch === undefined ? null : errorCode(mismatch);
	const authorizationError = socket.authorized ? null : errorCode(socket.authorizationError);
	return {
		ok: true,
		protocol: socket.getProtocol() ?? 'unknown',
		authorizationError,
		identityError: identity,
		certificate: {
			dnsNames: names,
			validFrom: isoDate(certificate.valid_from),
			validTo: isoDate(certificate.valid_to),
			issuer: [certificate.issuer?.CN ?? certificate.issuer?.O ?? ''].flat().join(', ')
		}
	};
}

async function handshake(host: string, address: string, options: TlsProbeOptions): Promise<Handshake> {
	const result = await attempt(host, address, options, { minVersion: 'TLSv1.2' });
	if (!result.ok) {
		if (result.timedOut) {
			return { ok: false, error: 'timeout' };
		}
		return { ok: false, error: result.code === 'ECONNREFUSED' ? 'refused' : 'failed' };
	}
	const described = describe(host, result.socket);
	result.socket.destroy();
	return described;
}

async function versionSupport(host: string, address: string, options: TlsProbeOptions, version: SecureVersion): Promise<VersionSupport> {
	const result = await attempt(host, address, options, { minVersion: version, maxVersion: version, ciphers: LEGACY_CIPHERS });
	if (result.ok) {
		const negotiated = result.socket.getProtocol();
		result.socket.destroy();
		return negotiated === version ? 'accepted' : 'rejected';
	}
	if (result.timedOut || LOCAL_ERRORS.has(result.code)) {
		return 'unknown';
	}
	return 'rejected';
}

export async function probeTls(host: string, address: string, options: TlsProbeOptions = {}): Promise<TlsProbe> {
	const [main, tls10, tls11] = await Promise.all([
		handshake(host, address, options),
		versionSupport(host, address, options, 'TLSv1'),
		versionSupport(host, address, options, 'TLSv1.1')
	]);
	return { handshake: main, tls10, tls11 };
}
