import { ALGOS } from './consts.js';
import { decodeRequestToken } from './jwt.js';

/**
 * Fetches a JSON Web Key (JWK) from Google Firebase for the given key ID (kid).
 *
 * @param {string} kid - The key ID of the JWK to fetch.
 * @returns {Promise<CryptoKey | null>} A promise that resolves to the imported JWK if found, or null if not found.
 * @throws {Error} - If there's an error fetching or importing the JWK.
*/

export async function getFirebaseJWK(kid) {
	const resp = await fetch('https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com', {
		headers: { Accept: 'application/json' },
		referrerPolicy: 'no-referrer',
		crossOrigin: 'anonymous',
	});

	const data = await resp.json() ?? [];

	const key = data.keys.find(key => key.kid === kid);

	if (typeof key === 'object') {
		return await crypto.subtle.importKey(
			'jwk',
			key,
			ALGOS[key.alg],
			false,
			['verify'],
		);
	} else {
		return null;
	}
}


/**
 *  Decodes and validates a Firebase request token from the Authorization header.
 *
 * @param {Request} req - The HTTP request object.
 * @returns {Promise<Object>} A promise that resolves to the validated payload object.
 * @throws {TypeError} - If the provided object is not a Request object.
 * @throws {Error} - If the token is invalid (e.g., expired, malformed signature, unexpected payload content).
 */
export async function decodeFirebaseAuthRequestToken(req) {
	if (! (req instanceof Request)) {
		throw new TypeError('Not a request object.');
	} else {
		const now = parseInt(Date.now() / 1000);
		const { header, payload, signature, data } = decodeRequestToken(req);

		if (typeof payload !== 'object') {
			throw new TypeError('Invalid payload in token.');
		} else if (! ['alg', 'kid'].every(prop => prop in header)) {
			throw new Error('Invalid token header.');
		} else if (! ['name', 'auth_time', 'iss', 'user_id', 'iat', 'exp', 'email'].every(prop => prop in payload)) {
			throw new Error('Invalid token payload.');
		} else if (payload.iat > now) {
			throw new Error('Token cannot have been generated in future.');
		} else if (payload.exp > now) {
			throw new Error('Token is expired.');
		} else if (!await crypto.subtle.verify(
			ALGOS[header.alg],
			await getFirebaseJWK(header.kid),
			signature,
			data,
		)) {
			throw new Error('Token signature did not validate.');
		} else {
			return payload;
		}
	}
}
