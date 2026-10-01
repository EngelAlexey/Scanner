import { isPublicAddress, type AddressPolicy } from '../../src/net/address-policy.ts';

export function testAddressPolicy(port: number): AddressPolicy {
	return {
		name: 'test',
		isAllowedAddress: (address) => address === '127.0.0.1' || isPublicAddress(address),
		isAllowedPort: (candidate) => candidate === port
	};
}
