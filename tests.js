import { generateJWK, createOriginAuthToken, verifyJWT, ALGOS } from './jwk-utils.js';

console.time('Running tests');

const results = await Promise.allSettled(Object.keys(ALGOS).map(async alg => {
	const keys = await generateJWK(alg);
	const token = await createOriginAuthToken('https://example.com', keys);
	const decoded = await verifyJWT(token, keys);

	if (decoded === null) {
		throw new Error(`Error decoding token: ${token}`);
	} else {
		return null;
	}
}));

const errs = results.filter(result => result.status === 'rejected');

console.timeEnd('Running tests');

if (errs.length === 1) {
	throw errs[0].reason;
} else if (errs.length !== 0) {
	throw new AggregateError(errs.map(err => err.reason));
}
