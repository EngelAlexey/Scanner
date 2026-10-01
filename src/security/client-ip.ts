import { createHmac } from 'node:crypto';
import { ipAddress } from '@vercel/functions/headers';
import ipaddr from 'ipaddr.js';

const HOUR_MS = 3_600_000;
const IPV6_PREFIX_BYTES = 8;

export type ClientIp = { readonly ok: true; readonly address: string; readonly hash: string } | { readonly ok: false };

export function startOfHour(now: Date): Date {
	return new Date(Math.floor(now.getTime() / HOUR_MS) * HOUR_MS);
}

export function normalizeClientIp(raw: string): string | undefined {
	const value = raw.trim();
	if (ipaddr.IPv4.isValidFourPartDecimal(value)) {
		return ipaddr.IPv4.parse(value).toString();
	}
	if (!ipaddr.IPv6.isValid(value)) {
		return undefined;
	}
	const address = ipaddr.process(value);
	if (address.kind() === 'ipv4') {
		return address.toString();
	}
	const prefix = address.toByteArray().slice(0, IPV6_PREFIX_BYTES);
	const network = ipaddr.fromByteArray([...prefix, ...new Array<number>(16 - IPV6_PREFIX_BYTES).fill(0)]);
	return `${network.toString()}/64`;
}

export function hashClientIp(normalized: string, secret: string, now: Date): string {
	return createHmac('sha256', secret).update(`${startOfHour(now).toISOString()}|${normalized}`).digest('base64url');
}

export function readClientIp(request: Request, secret: string, now: Date): ClientIp {
	const address = ipAddress(request);
	const normalized = address === undefined ? undefined : normalizeClientIp(address);
	if (address === undefined || normalized === undefined) {
		return { ok: false };
	}
	return { ok: true, address: address.trim(), hash: hashClientIp(normalized, secret, now) };
}
