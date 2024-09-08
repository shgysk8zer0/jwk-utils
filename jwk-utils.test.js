import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generateJWK, createOriginAuthToken, ALGOS, verifyRequestToken, HS256, importJWK, exportJWK, verifyJWT } from './jwk-utils.js';
import events from 'node:events';

const invalidKey = await generateJWK(HS256);
const signal = AbortSignal.timeout(60_000);
const algs = Object.keys(ALGOS);

// Do not warn about abort event listeners causing memory leaks.
events.setMaxListeners(algs.length * 5, signal);

describe('JWK Utils Tests', async () => {
	for (const alg of algs) {
		const keys = await generateJWK(alg);

		const token = await createOriginAuthToken('https://example.com', keys, {
			subject: 'https://api.example.com',
			entitlements: ['data:read', 'data:write']
		});

		test(`${alg} algorithm valid token`, { signal }, async () => {
			const url = new URL('https://api.example.com');

			const decoded = await verifyRequestToken(new Request(url, {
				mode: 'cors',
				credentials: 'include',
				headers: {
					Origin: 'https://example.com',
					Authorization: `Bearer ${token}`,
				},
			}), keys, { entitlements: ['data:read', 'data:write'] });

			if (decoded instanceof Error || decoded instanceof DOMException) {
				assert.fail(decoded);
			} else {
				assert.notEqual(null, 'Token should be decoded successfully');
				assert.equal(typeof decoded, 'object', 'Decoded token should be an object');
			}
		});

		test(`${alg} entitlements/permissions`, { signal }, async () => {
			const result = await verifyJWT(token, keys, { entitlements: ['data:delete'] });
			assert.ok(result instanceof Error, 'Should not verify with missing entitlements.');
		});

		test(`${alg} algorithm invalid tokens`, { signal }, async () => {
			const decoded = await verifyJWT('dfjhgdhbfgkdfg.dfdjgkdfgk.dfjhgjf', keys);
			assert.ok(decoded instanceof Error, 'Invalid tokens should return an error.');
		});

		test(`${alg} invallid key`, { signal }, async () => {
			const result = await verifyJWT(token, invalidKey);
			assert.ok(result instanceof Error, 'Should not verify tokens from other keys.');
		});

		test(`${alg} key/keypair import & export`, { signal }, async () => {
			if (keys instanceof CryptoKey) {
				const exported = await exportJWK(keys);
				const imported = await importJWK(exported);
				assert.ok(imported instanceof CryptoKey, 'Imported key should be a crypto key.');
			}
		});
	}
});
