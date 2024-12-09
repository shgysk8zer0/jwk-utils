import '@shgysk8zer0/polyfills';
import { describe, test } from 'node:test';
import assert from 'node:assert';
import { signal } from './signal.test.js';
import { createJWT, createUnsecuredJWT, decodeToken, decodeRequestToken, verifyHeader, verifyPayload, verifyJWT, verifyRequestToken, refreshJWT, isVerifiedPayload } from './jwt.js';
import { generateJWK } from './jwk.js';
import { ES256, HS256 } from './consts.js';

describe('Test JWT functions', { concurrency: true }, async () => {
	const now = Math.floor(Date.now() / 1000);
	const { publicKey, privateKey } = await generateJWK(ES256);
	const invalidKey = await generateJWK(HS256);

	const createTestToken = async ({ iat = now, entitlements = [], ttl = 60, sub = 'tests', ...claims } = {}, key) => {
		return await createJWT({
			sub: sub,
			iat: iat,
			exp: iat + ttl,
			nbf: iat,
			jti: crypto.randomUUID(),
			entitlements: entitlements,
			...claims,
		}, key);
	};

	test('Decodes token from request', { signal }, async () => {
		const token = await createJWT({ iat: now }, privateKey);
		const url = new URL('https://example.com');
		url.searchParams.set('token', token);
		const req = new Request(url);
		const result = decodeRequestToken(req, { claims: ['iat'] });
		assert.notEqual(result, null, 'Request tokens should decode correctly.');
	});

	test('Returns error when missing claims', { signal }, async () => {
		const token = await createJWT({ iat: now }, privateKey);
		const decoded = decodeToken(token, { claims: ['sub'] });
		const result = verifyPayload(decoded.payload, { claims: ['sub'] });
		assert.ok(result instanceof Error, 'Tokens missing expected claims should return an error.');
	});

	test('Create and verify JWTs', { signal }, async () => {
		const token = await createTestToken({ entitlements: ['db:read'] }, privateKey);
		const result = await verifyJWT(token, publicKey, { claims: ['sub', 'iat', 'nbf', 'exp', 'jti'], entitlements: ['db:read'] });

		assert.ok(typeof token === 'string', 'Created JWTs are strings');

		if (result instanceof Error) {
			assert.fail(result);
		} else {
			assert.notEqual(result, null, 'Verified tokens should not return null.');
			assert.ok(result?.entitlements?.includes('db:read'), 'Token decodes correctly.');
		}
	});

	test('Additional checks on JWTs should pass when valid', { signal }, async () => {
		const jti = crypto.randomUUID();
		const latitude = 3.1415;
		const longitude = 2.7818;
		const token = await createTestToken({
			roles: ['admin'],
			jti,
			location: { latitude, longitude },
		}, privateKey);

		const result = await verifyJWT(token, publicKey, { roles: ['admin', 'user'], jti, location: { latitude, longitude }});

		assert.ok(result.jti === jti, 'Token should pass additional tests and return the payload onject.');
	});

	test('Resource owners should bypass role/entitements checks.', { signal }, async () => {
		const sub = crypto.randomUUID();
		const latitude = 3.1415;
		const longitude = 2.7818;

		const token = await createTestToken({
			sub,
			roles: ['admin'],
			entitlements: ['comment:create'],
			jti: crypto.randomUUID(),
			location: { latitude, longitude },
		}, privateKey);

		const result = await verifyJWT(token, publicKey, {
			sub,
			roles: ['user'],
			entitlements: ['comment:delete'],
			claims: ['jti', 'sub', 'roles', 'entitlements'],
			owner: sub,
			location: { latitude, longitude },
		});

		assert.ok(! (result instanceof Error), 'Resource owners should bypass permission checks.');
	});

	test('Additional checks on JWTs should fail when invalid', { signal }, async () => {
		const jti = crypto.randomUUID();
		const latitude = 3.1415;
		const longitude = 2.7818;
		const user = crypto.randomUUID();
		const token = await createTestToken({
			sub: user,
			roles: ['user'],
			jti,
			location: { latitude, longitude },
		}, privateKey);

		const [invlidRole, invalidJTI, invalidLocation, missingProp, ownerInvalid] = await Promise.all([
			verifyJWT(token, publicKey, { roles: ['admin'], jti, location: { latitude, longitude } }),
			verifyJWT(token, publicKey, { roles: ['user'], jti: crypto.randomUUID(), location: { latitude, longitude } }),
			verifyJWT(token, publicKey, { roles: ['user'], jti: crypto.randomUUID(), location: { latitude: 0, longitude: 0 } }),
			verifyJWT(token, publicKey, { roles: ['user'], jti, location: { latitude: 0, longitude: 0, dne: true } }),
			verifyJWT(token, publicKey, { roles: ['user'], sub: user, user, jti, location: { latitude: 0, longitude: 0, dne: true } }),
		]);

		assert.ok(invlidRole instanceof Error, 'Invalid roles should return an error.');
		assert.ok(invalidJTI instanceof Error, 'Mismatched `jti` should return an error.');
		assert.ok(invalidLocation instanceof Error, 'Mismatched `location` should return an error.');
		assert.ok(missingProp instanceof Error, 'Missing properties should return an error.');
		assert.ok(ownerInvalid instanceof Error, 'Valid owner with missing claims should still error.');
	});

	test('Test refreshing un-expired tokens', { signal }, async () => {
		const iat = Math.floor(Date.now() / 1000) - 50;
		const oldToken = await createJWT({
			iat,
			exp: iat + 60,
		}, privateKey);

		const renewedToken = await refreshJWT(oldToken, { publicKey, privateKey });
		const result = await verifyJWT(renewedToken, publicKey);

		if (renewedToken instanceof Error) {
			assert.fail(renewedToken);
		} else if (result instanceof Error) {
			assert.fail(result);
		} else {
			assert.ok(result?.iat > iat, 'Renewed token should be issued at a later time.');
			assert.ok(result?.exp > (iat + 60), 'Renewed token should expire later.');
			assert.notEqual(result, null, 'Verified tokens should not return null.');
		}
	});

	test('Test tokens in `Request`s', { signal }, async () => {
		const token = await createTestToken({ sub: 'request' }, privateKey);
		const req = new Request('https://example.com', {
			headers: { 'Authorization': `Bearer ${token}` },
		});

		const result = await verifyRequestToken(req, publicKey);

		if (result instanceof Error) {
			assert.fail(result);
		} else {
			assert.notEqual(result, null, 'Verified tokens should not be null.');
		}
	});

	test('Test invalid JWTs', { signal }, async () => {
		const token = await createTestToken();
		const result = await verifyJWT(token + 'a', publicKey);

		assert.ok(result instanceof Error, 'Invalid tokens should return an error.');
	});

	test('Test expired tokens', { signal }, async () => {
		const token = await createTestToken({ iat: now - 1000 }, privateKey);
		const result = await verifyJWT(token, publicKey);

		assert.ok(typeof token === 'string', 'Created JWTs are strings');
		assert.ok(result instanceof Error, 'Expired tokens should result in `Error`s');
	});

	test('Test bad signature/wrong key', { signal }, async () => {
		const token = await createTestToken({ iat: now - 1000 }, invalidKey);
		const result = await verifyJWT(token, publicKey);

		assert.ok(result instanceof Error, 'Tokens from invalid keys should result in `Error`s');
	});

	test('Test missing entitlements', { signal }, async () => {
		const token = await createTestToken({ entitlements: ['db:read'] }, privateKey);
		const result = await verifyJWT(token, publicKey, { entitlements: ['db:read', 'db:write'] });

		assert.ok(result instanceof Error, 'JWTs with missing entitlements should result in `Error`s');
	});

	test('Create and decode unsecure JWT', { signal }, async () => {
		const now = Math.floor(Date.now() / 1000);
		const token = createUnsecuredJWT({ iss: 'tests', iat: now, exp: now + 10 });
		const decoded = decodeToken(token);

		assert.ok(typeof token === 'string', 'Generated token should be a string');
		assert.ok(verifyHeader(decoded?.header), 'Decoded token header should be valid');
		assert.ok(isVerifiedPayload(decoded?.payload), 'Decoded token payload should be valid');
		assert.notEqual(decoded, null, 'Decoded tokens should not return null.');
	});
});
