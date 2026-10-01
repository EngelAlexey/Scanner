import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { checkPolicy, isPublicAddress, productionAddressPolicy } from '../src/net/address-policy.ts';
import { testAddressPolicy } from './helpers/test-policy.ts';

const PUBLIC = [
	'8.8.8.8',
	'1.1.1.1',
	'76.76.21.21',
	'100.63.255.255',
	'172.15.255.255',
	'172.32.0.0',
	'2606:4700:4700::1111',
	'2001:4860:4860::8888'
];

const NOT_PUBLIC = [
	'0.0.0.0',
	'10.0.0.0',
	'10.255.255.255',
	'100.64.0.1',
	'100.100.100.200',
	'127.0.0.1',
	'127.0.0.2',
	'169.254.169.254',
	'169.254.170.2',
	'172.16.0.0',
	'172.31.255.255',
	'192.0.0.192',
	'192.0.2.1',
	'192.168.1.1',
	'198.18.0.1',
	'203.0.113.9',
	'224.0.0.1',
	'255.255.255.255',
	'::',
	'::1',
	'::ffff:127.0.0.1',
	'::ffff:10.0.0.1',
	'::7f00:1',
	'64:ff9b::a00:1',
	'2002:a00:1::',
	'2001::1',
	'2001:db8::1',
	'fc00::1',
	'fd00:ec2::254',
	'fe80::1',
	'ff02::1',
	'not-an-address'
];

describe('isPublicAddress', () => {
	for (const address of PUBLIC) {
		test(`allows ${address}`, () => {
			assert.equal(isPublicAddress(address), true);
		});
	}
	for (const address of NOT_PUBLIC) {
		test(`denies ${address}`, () => {
			assert.equal(isPublicAddress(address), false);
		});
	}
});

describe('production policy', () => {
	test('allows only ports 80 and 443', () => {
		assert.equal(productionAddressPolicy.isAllowedPort(80), true);
		assert.equal(productionAddressPolicy.isAllowedPort(443), true);
		assert.equal(productionAddressPolicy.isAllowedPort(8080), false);
		assert.equal(productionAddressPolicy.isAllowedPort(22), false);
	});

	test('a test policy cannot run on Vercel', () => {
		const previous = process.env.VERCEL;
		process.env.VERCEL = '1';
		try {
			assert.throws(() => checkPolicy(testAddressPolicy(8080)), /cannot run on Vercel/);
			assert.equal(checkPolicy(productionAddressPolicy), productionAddressPolicy);
		} finally {
			if (previous === undefined) {
				delete process.env.VERCEL;
			} else {
				process.env.VERCEL = previous;
			}
		}
	});
});
