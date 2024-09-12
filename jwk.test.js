import '@shgysk8zer0/polyfills';
import { describe, test } from 'node:test';
import assert from 'node:assert';
import { generateJWK, base64EncodeJWK, importJWKFromBase64, importRawKey, createJWKFile, loadJWKFromBlob, fetchJWK, importJWK, exportJWK } from './jwk.js';
import { HS256 } from './consts.js';
import { signal } from './signal.test.js';
import { ALGOS } from './consts.js';

const algos = Object.keys(ALGOS);

// Make concurrent due to extensive async keygen operations
describe('Test JWK/key functions', { concurrency: true }, async () => {
	const key = await generateJWK(HS256);
	const skip = ! (key instanceof CryptoKey);

	for (const algo of algos) {
		test(`Generate key/key pair using ${algo}`, { signal }, async () => {
			const keys = await generateJWK(algo);

			if (keys instanceof Error) {
				assert.fail(key);
			} else if ('publicKey' in keys) {
				assert.ok(keys.publicKey instanceof CryptoKey, `${algo} key pair should have a public key`);
				assert.ok(keys.privateKey instanceof CryptoKey,  `${algo} key pair should have a private key`);
			} else {
				assert.ok(keys instanceof CryptoKey, `${algo} should create a CryptoKey`);
			}
		});
	}

	test('Import symmetric key from raw', { signal }, async () => {
		const key = await importRawKey(crypto.getRandomValues(new Uint8Array(256)), { algorithm: HS256 });
		assert.ok(key instanceof CryptoKey, '`importRawKey` should return a `CryptoKey`');
	});

	test('Import/export JWK files', { signal }, async () => {
		const file = await createJWKFile(key);
		const imported = await loadJWKFromBlob(file);
		const blob = URL.createObjectURL(file);
		const fetched = await fetchJWK(blob); // Cannot easily fetch from a remote URL, but this works
		assert.ok(file instanceof File, '`createJWKFile` should return a `File`');
		assert.ok(imported instanceof CryptoKey, 'Importing from file should return a `CryptoKey`');
		assert.ok(fetched instanceof CryptoKey, '`fetchJWK` should return a `CryptoKey`');
	});

	test('Key generated is a `CryptoKey`.', { signal }, () => assert.ok(key instanceof CryptoKey, 'Generated key should be a `CryptoKey'));

	test('Base64 encoding / decoding of keys', { signal, skip }, async () => {
		const encoded = await base64EncodeJWK(key);

		if (encoded instanceof Error) {
			assert.fail(encoded);
		} else {
			const decoded = await importJWKFromBase64(encoded);

			if (decoded instanceof Error) {
				assert.fail(decoded);
			} else {
				assert.ok(decoded instanceof CryptoKey, 'Importing from base64 string should result in a `CryptoKey`');
			}
		}
	});

	test('Export and import key', { signal }, async () => {
		const exported = await exportJWK(key);
		const imported = await importJWK(exported);
		assert.ok(imported instanceof CryptoKey, 'Imported key should be a crypto key.');
	});
});
