import { ALGOS } from './consts.js';
import { decodeRequestToken, decodeToken } from './jwt.js';

/**
 * Fetches a JSON Web Key (JWK) from Google Firebase for the given key ID (kid).
 *
 * This function retrieves the JWK set from the Google Firebase metadata endpoint, locates the key with the specified `kid`, and imports it using the Web Crypto API.
 *
 * @param {string} kid - The key ID (kid) of the JWK to fetch.
 * @property {boolean} [extractable=false] - Whether the imported key is extractable. Defaults to false.
 * @property {FetchInit | object} [fetchInit] - (Optional) An object containing options to pass directly to the `fetch` function.
 *
 * @returns {Promise<CryptoKey | null>}
 *  - Resolves to the imported JWK object if the key with the specified `kid` is found.
 *  - Resolves to `null` if the key is not found.
 *  - Rejects with an `Error` if there's an error fetching, parsing, or importing the JWK.
 */
export async function getFirebaseJWK(kid, extractable = false, fetchInit = {}) {
	try {
		const resp = await fetch('https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com', {
			headers: { Accept: 'application/json' },
			...fetchInit,
		});

		const data = await resp.json() ?? [];

		const key = data.keys.find(key => key.kid === kid);

		if (typeof key === 'object') {
			return await crypto.subtle.importKey(
				'jwk',
				key,
				ALGOS[key.alg],
				extractable,
				['verify'],
			);
		} else {
			return null;
		}
	} catch {
		return null;
	}
}

/**
 * Fetches a JSON Web Key (JWK) from Google Firebase for the given key ID (kid).
 *
 * @param {string} token - The Firebase ID token for a user.
 * @param {FetchInit} fetchInit - (Optional) An object containing options for the fetch request.
 * @returns {Promise<object | null>} A promise that resolves to the validated payload object.
 */
export async function verifyFirebaseIdToken(token, fetchInit = {}) {
	const { header, payload, signature, data } = decodeToken(token);

	if (typeof payload !== 'object' || payload === null || typeof header !== 'object' || header === null) {
		return null;
	} else if (! ['name', 'auth_time', 'iss', 'user_id', 'iat', 'exp', 'email'].every(prop => prop in payload)) {
		return null;
	} else if (! payload.iss.startsWith('https://securetoken.google.com/')) {
		return null;
	} else if (! await crypto.subtle.verify(
		ALGOS[header.alg],
		await getFirebaseJWK(header.kid, false, fetchInit),
		signature,
		data,
	)) {
		return null;
	} else {
		return payload;
	}
}

/**
 *  Decodes and validates a Firebase request token from the Authorization header.
 *
 * @param {Request} req - The HTTP request object.
 * @returns {Promise<object | null>} A promise that resolves to the validated payload object.
 * @throws {TypeError} - If the provided object is not a Request object.
 */
export async function decodeFirebaseAuthRequestToken(req, fetchInit = {}) {
	if (! (req instanceof Request)) {
		throw new TypeError('Not a request object.');
	} else {
		const { header, payload, signature, data } = decodeRequestToken(req);

		if (typeof payload !== 'object' || payload === null || typeof header !== 'object' || header === null) {
			return null;
		} else if (! ['name', 'auth_time', 'iss', 'user_id', 'iat', 'exp', 'email'].every(prop => prop in payload)) {
			return null;
		} else if (! payload.iss.startsWith('https://securetoken.google.com/')) {
			return null;
		} else if (! await crypto.subtle.verify(
			ALGOS[header.alg],
			await getFirebaseJWK(header.kid, false, fetchInit),
			signature,
			data,
		)) {
			return null;
		} else {
			return payload;
		}
	}
}
