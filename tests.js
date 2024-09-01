import { generateJWK, createOriginAuthToken, decodeOriginToken, ALGOS } from './jwk-utils.js';

const start = performance.now();

const results = await Promise.allSettled(Object.keys(ALGOS).map(async alg => {
	const keys = await generateJWK(alg);
	const { publicKey, privateKey } = keys instanceof CryptoKey ? { publicKey: keys, privateKey: keys } : keys;
	const token = await createOriginAuthToken('https://example.com', privateKey);
	const decoded = await decodeOriginToken(token, 'https://example.com', publicKey);

	if (decoded === null) {
		throw new Error('Error decoding token.');
	} else if (await decodeOriginToken('njkdfnfgkjfd', publicKey) !== null) {
		throw new Error('Decoding invalid tokens should return `null`.');
	}
}));

const errs = results.filter(result => result.status === 'rejected');

console.info(`Test completed in ${performance.now() - start}ms.`);

if (errs.length === 1) {
	throw errs[0].reason;
} else if (errs.length !== 0) {
	throw new AggregateError(errs.map(err => err.reason));
}
