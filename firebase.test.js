import { describe, test } from 'node:test';
import assert from 'node:assert';
import { signal } from './signal.test.js';
import { getFirebaseJWK } from './firebase.js';


describe('Firebase JWT tests', async () => {
	const KID = '02100716fdd904e5b4d49116ff5dbdfc98999401';

	test('Import Firebase public key', { signal }, async () => {
		const key = await getFirebaseJWK(KID,{ signal });
		assert.ok(key instanceof CryptoKey, '`getFirebaseJWK` should return a `CryptoKey`.');
	});

	test.todo('Cannot test Firebase Auth ID tokens without a token to test.');
});
