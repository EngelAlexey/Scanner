import { isPublicAddress, type AddressPolicy } from '../../src/net/address-policy.ts';

export function testAddressPolicy(ports: number | readonly number[], extraAddresses: readonly string[] = []): AddressPolicy {
	const allowedPorts = typeof ports === 'number' ? [ports] : ports;
	return {
		name: 'test',
		isAllowedAddress: (address) => address === '127.0.0.1' || extraAddresses.includes(address) || isPublicAddress(address),
		isAllowedPort: (candidate) => allowedPorts.includes(candidate)
	};
}
