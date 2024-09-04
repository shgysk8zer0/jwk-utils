import { generateJWK, createOriginAuthToken, ALGOS, verifyRequestToken } from './jwk-utils.js';

console.time('Running tests');

const results = await Promise.allSettled(Object.keys(ALGOS).map(async alg => {
	const keys = await generateJWK(alg);
	const token = await createOriginAuthToken('https://example.com', keys, { subject: 'https://api.example.com' });
	const url = new URL('https://api.example.com');

	const decoded = await verifyRequestToken(new Request(url, {
		mode: 'cors',
		credentials: 'include',
		headers: {
			Origin: 'https://example.com',
			Authorization: `Bearer ${token}`,
		},
	}), keys);

	if (decoded === null) {
		throw new Error(`Error decoding token: ${token}`);
	} else if (decoded instanceof Error) {
		throw decoded;
	} else {
		return null;
	}
}));

const errs = results.filter(result => result.status === 'rejected').map(result => result.reason);

console.timeEnd('Running tests');

if (errs.length === 1) {
	throw errs[0].reason;
} else if (errs.length !== 0) {
	throw new AggregateError(errs);
}
