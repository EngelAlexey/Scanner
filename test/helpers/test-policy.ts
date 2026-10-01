import { isPublicAddress, type AddressPolicy } from '../../src/net/address-policy.ts';

export function testAddressPolicy(port: number, extraAddresses: readonly string[] = []): AddressPolicy {
	return {
		name: 'test',
		isAllowedAddress: (address) => address === '127.0.0.1' || extraAddresses.includes(address) || isPublicAddress(address),
		isAllowedPort: (candidate) => candidate === port
	};
}
