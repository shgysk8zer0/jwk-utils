import { ALGOS, LEEWAY } from './consts.js';
import { decodeRequestToken, decodeToken, verifyHeader, verifyPayload } from './jwt.js';

const REQUIRED_CLAIMS = ['name', 'auth_time', 'iss', 'user_id', 'iat', 'exp', 'email'];

/**
 * Fetches a JSON Web Key (JWK) from Google Firebase for the given key ID (kid).
 *
 * This function retrieves the JWK set from the Google Firebase metadata endpoint, locates the key with the specified `kid`, and imports it using the Web Crypto API.
 *
 * @param {string} kid - The key ID (kid) of the JWK to fetch.
 * @property {boolean} [extractable=false] - Whether the imported key is extractable. Defaults to false.
 * @property {RequestInit} [fetchInit] - (Optional) An object containing options to pass directly to the `fetch` function.
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
 * @param {RequestInit} fetchInit - (Optional) An object containing options for the fetch request.
 * @returns {Promise<object | null>} A promise that resolves to the validated payload object.
 */
export async function verifyFirebaseIdToken(token, fetchInit = {}) {
	const decoded = decodeToken(token);

	if (decoded instanceof Error) {
		return decoded;
	} else if (! verifyHeader(decoded.header) || decoded.header.alg === 'none') {
		return new Error('Invalid JWT header.');
	} else if ( ! verifyPayload(decoded.payload)) {
		return new Error('Invalid JWT paylod.');
	} else if (! ['name', 'auth_time', 'iss', 'user_id', 'iat', 'exp', 'email'].every(prop => prop in decoded.payload)) {
		return new TypeError('Missing required fields in JWT payload.');
	} else if (! decoded.payload.iss.startsWith('https://securetoken.google.com/')) {
		return new TypeError('JWT payload is not from a Google/Firebase origin.');
	} else if (! await crypto.subtle.verify(
		ALGOS[decoded.header.alg],
		await getFirebaseJWK(decoded.header.kid, false, fetchInit),
		decoded.signature,
		decoded.data,
	)) {
		return new Error('Unable to verify JWT signature.');
	} else {
		return decoded.payload;
	}
}

/**
 *  Decodes and validates a Firebase request token from the Authorization header.
 *
 * @param {Request} req - The HTTP request object.
 * @param {RequestInit} [fetchInit={}] Config for fetch request.
 * @param {object} [options] - Optional options
 * @param {number} [options.leeway=60] - The allowed clock skew in seconds (default: 60).
 * @returns {Promise<object | Error>} A promise that resolves to the validated payload object or any error that occurs.
 * @throws {TypeError} If the provided object is not a Request object.
 */
export async function verifyFirebaseAuthRequestToken(req, fetchInit = {}, { leeway = LEEWAY } = {}) {
	if (! (req instanceof Request)) {
		throw new TypeError('Not a request object.');
	} else {
		const decoded = decodeRequestToken(req, { leeway, claims: REQUIRED_CLAIMS });

		if (decoded instanceof Error) {
			return decoded;
		} else if (decoded.header.alg === 'none') {
			return new Error('Invalid JWT algorithm in header.');
		} else if (! decoded.payload.iss.startsWith('https://securetoken.google.com/')) {
			return new TypeError('JWT payload is not from a Google/Firebase origin.');
		} else if (! await crypto.subtle.verify(
			ALGOS[decoded.header.alg],
			await getFirebaseJWK(decoded.header.kid, false, fetchInit),
			decoded.signature,
			decoded.data,
		)) {
			return new Error('Unable to verify JWT signature.');
		} else {
			return decoded.payload;
		}
	}
}
