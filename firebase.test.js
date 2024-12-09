import '@shgysk8zer0/polyfills';
import { describe, test } from 'node:test';
import assert from 'node:assert';
import { signal } from './signal.test.js';
import { MIME_TYPE } from './consts.js';
import { getFirebasePublicKey, verifyFirebaseIdToken } from './firebase.js';

describe('Firebase JWT tests', async () => {
	test('Import Firebase public key', { signal }, async () => {
		const key = await getFirebasePublicKey(false, { signal, referrerPolicy: 'no-referrer', mode: 'cors', headers: { Accept: MIME_TYPE }});
		assert.ok(key instanceof CryptoKey, '`getFirebaseJWK` should return a `CryptoKey`.');
	});

	// Set token via `export ID_TOKEN='...' to test. I'm not including an actual token in the codebase,
	// and I cannot find a public token for testing.
 	test('Check Firebase ID token, if `ID_TOKEN` set in environment', { signal, skip: typeof process.env.ID_TOKEN !== 'string' }, async () => {
		const result = await verifyFirebaseIdToken(process.env.ID_TOKEN, { signal });
		assert.ok(! (result instanceof Error), 'Firebase id token should be valid.');
	});
});
