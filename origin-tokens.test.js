import '@shgysk8zer0/polyfills';
import { generateJWK } from './jwk.js';
import { verifyRequestOriginToken, authenticateRequest, createOriginAuthToken } from './origin-tokens.js';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { signal } from './signal.test.js';

describe('JWK Utils Tests', async () => {
	test('Test request / origin token', { signal }, async () => {
		const { publicKey, privateKey } = await generateJWK();
		const req = new Request('https://api.example.com', { headers: { Origin: 'https://example.com' }});
		await authenticateRequest(req, privateKey);
		const result = await verifyRequestOriginToken(req, publicKey);

		if (result instanceof Error || result instanceof DOMException) {
			assert.fail(result);
		} else {
			assert.notEqual(result, null, 'Token should be decoded successfully');
			assert.equal(typeof result, 'object', 'Decoded token should be an object');
		}
	});

	test('Test invalid origin for origin/request token', { signal }, async () => {
		const { publicKey, privateKey } = await generateJWK();
		const token = await createOriginAuthToken('https://example.com', privateKey);
		const req = new Request('https://api.example.com', {
			headers: {
				Origin: 'https://invalid.com',
				Authorization: `Bearer ${token}`,
			},
		});

		const result = await verifyRequestOriginToken(req, publicKey);

		assert.ok(result instanceof Error, 'Origin tokens should return error on incorrect origins.');
	});
});
