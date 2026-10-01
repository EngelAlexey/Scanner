import ipaddr from 'ipaddr.js';

type Range4 = [ipaddr.IPv4, number];
type Range6 = [ipaddr.IPv6, number];

function ranges4(cidrs: readonly string[]): Range4[] {
	return cidrs.map((cidr) => ipaddr.IPv4.parseCIDR(cidr));
}

function ranges6(cidrs: readonly string[]): Range6[] {
	return cidrs.map((cidr) => ipaddr.IPv6.parseCIDR(cidr));
}

const IPV4_DENIED = ranges4([
	'0.0.0.0/8',
	'10.0.0.0/8',
	'100.64.0.0/10',
	'127.0.0.0/8',
	'169.254.0.0/16',
	'172.16.0.0/12',
	'192.0.0.0/24',
	'192.0.2.0/24',
	'192.31.196.0/24',
	'192.52.193.0/24',
	'192.88.99.0/24',
	'192.168.0.0/16',
	'192.175.48.0/24',
	'198.18.0.0/15',
	'198.51.100.0/24',
	'203.0.113.0/24',
	'224.0.0.0/4',
	'240.0.0.0/4'
]);

const IPV6_GLOBAL_UNICAST = ranges6(['2000::/3']);
const IPV6_DENIED = ranges6(['2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20']);

export function isPublicAddress(address: string): boolean {
	if (!ipaddr.isValid(address)) {
		return false;
	}
	const parsed = ipaddr.process(address);
	if (parsed.kind() === 'ipv4') {
		const ip = parsed as ipaddr.IPv4;
		return !IPV4_DENIED.some((range) => ip.match(range));
	}
	const ip = parsed as ipaddr.IPv6;
	return IPV6_GLOBAL_UNICAST.some((range) => ip.match(range)) && !IPV6_DENIED.some((range) => ip.match(range));
}

export type AddressPolicy = {
	readonly name: string;
	isAllowedAddress(address: string): boolean;
	isAllowedPort(port: number): boolean;
};

export const productionAddressPolicy: AddressPolicy = Object.freeze({
	name: 'production',
	isAllowedAddress: isPublicAddress,
	isAllowedPort: (port: number) => port === 80 || port === 443
});

export function checkPolicy(policy: AddressPolicy): AddressPolicy {
	if (process.env.VERCEL && policy !== productionAddressPolicy) {
		throw new Error(`Address policy "${policy.name}" cannot run on Vercel`);
	}
	return policy;
}
