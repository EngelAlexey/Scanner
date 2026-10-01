import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import tls from 'node:tls';

const DIRECTORY = new URL('../fixtures/tls/', import.meta.url);

export function fixture(name: string): string {
	return readFileSync(new URL(name, DIRECTORY), 'utf8');
}

export const TEST_CA = fixture('ca.pem');

export type TlsServer = {
	readonly port: number;
	close(): Promise<void>;
};

export type TlsServerOptions = {
	readonly certificate: string;
	readonly chain?: boolean;
	readonly key?: string;
	readonly minVersion?: tls.SecureVersion;
	readonly maxVersion?: tls.SecureVersion;
	readonly ciphers?: string;
	readonly handler?: (socket: tls.TLSSocket) => void;
};

export async function startTlsServer(options: TlsServerOptions): Promise<TlsServer> {
	const certificate = fixture(options.certificate) + (options.chain === false ? '' : fixture('intermediate.pem'));
	const server = tls.createServer(
		{
			key: fixture(options.key ?? 'leaf.key'),
			cert: certificate,
			...(options.minVersion === undefined ? {} : { minVersion: options.minVersion }),
			...(options.maxVersion === undefined ? {} : { maxVersion: options.maxVersion }),
			...(options.ciphers === undefined ? {} : { ciphers: options.ciphers })
		},
		options.handler ?? ((socket) => socket.end())
	);
	server.on('tlsClientError', () => undefined);
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		port: (server.address() as AddressInfo).port,
		close: () => new Promise<void>((resolve) => server.close(() => resolve()))
	};
}
