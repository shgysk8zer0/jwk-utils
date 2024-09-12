import '@shgysk8zer0/polyfills';
import { describe, test } from 'node:test';
import assert from 'node:assert';
import { getPublicKey, getPrivateKey } from './env.js';
import { signal } from './signal.test.js';

describe('Test importing keys from environment', async () => {
	test('Import public key', { signal }, async () => {
		const publicKey = await getPublicKey();
		assert.ok(publicKey instanceof CryptoKey, '`getPublicKey` should return a `CryptoKey`');
	});

	test('Import private key', { signal }, async () => {
		const privateKey = await getPrivateKey();
		assert.ok(privateKey instanceof CryptoKey, '`getPrivateKey` should return a `CryptoKey`');
	});
});
