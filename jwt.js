import { ALPHABET as alphabet, ALGOS, AUTH } from './consts.js';
import { findKeyAlgo, getKeyId } from './utils.js';

/**
 * Verifies the header of a JSON Web Token (JWT).
 *
 * @param {object} options - An object containing the header properties.
 * @param {string} options.typ - The token type, expected to be 'JWT'.
 * @param {string} options.alg - The algorithm used to sign the token, must be a string and a known algorithm (from ALGOS).
 * @returns {boolean} True if the header is valid, false otherwise.
 */
export function verifyHeader({ typ, alg } = {}) {
	return (typ === 'JWT' && typeof alg === 'string' && alg in ALGOS);
}

/**
 * Verifies the payload of a JWT.
 *
 * @param {object} payload - The payload object to be verified.
 * @param {number} leeway (optional) - Number of seconds allowed for clock skew, defaults to 60.
 * @returns {boolean} True if the payload is valid, false otherwise.
 */
export function verifyPayload(payload, leeway = 60) {
	const now = Math.floor(Date.now() / 1000);

	if (typeof payload !== 'object' || payload === null) {
		return false;
	} else if (typeof payload.iat === 'number' && (payload.iat < (now - leeway))) {
		return false;
	} else if (typeof payload.nbf === 'number' && (payload.nbf < (now - leeway))) {
		return false;
	} else if (typeof payload.exp === 'number' && payload.exp < (now - leeway)) {
		return false;
	} else {
		return true;
	}
}

/**
 * Generates a JSON Web Token (JWT) using the provided payload and private key.
 *
 * @param {Object} payload - The payload data to include in the JWT.
 * @param {CryptoKey | CryptoKeyPair} key - The private/secret key or key pair used to sign the JWT.
 * @returns {Promise<string>} A promise that resolves to the generated JWT.
 * @throws {Error} - If there's an error generating the JWT.
 */
export async function createJWT(payload, key) {
	if (key instanceof CryptoKey) {
		const [name, algo] = findKeyAlgo(key);

		if (typeof name === 'string') {
			const encoder = new TextEncoder();
			const encodedHeader = encoder.encode(JSON.stringify({ alg: name, kid: await getKeyId(key), typ: 'JWT' })).toBase64({ alphabet }).replaceAll('=', '');
			const encodedPayload = encoder.encode(JSON.stringify(payload)).toBase64({ alphabet }).replaceAll('=', '');
			const signature = await crypto.subtle.sign(
				{ ...algo, ...key.algorithm },
				key,
				encoder.encode(`${encodedHeader}.${encodedPayload}`)
			);

			return `${encodedHeader}.${encodedPayload}.${new Uint8Array(signature).toBase64({ alphabet }).replaceAll('=', '')}`;
		} else {
			return null;
		}
	} else if (typeof key === 'object' && key !== null && key.privateKey instanceof CryptoKey) {
		return await createJWT(payload, key.privateKey);
	} else {
		throw new TypeError('Key must be either a CryptoKey or CrpytoKeyPair.');
	}
}


/**
 * Decodes a JSON Web Token (JWT) into its constituent parts.
 *
 * @param {string} jwt - The JWT to decode.
 * @returns {{ header: object, payload: object, signature: Uint8Array, data: Uint8Array }} An object containing the decoded header, payload, signature, and raw data.
 * @throws {Error} - If the JWT is malformed or cannot be decoded.
 */
export function decodeToken(jwt) {
	if (typeof jwt !== 'string') {
		throw new TypeError('JWT is not a string.');
	} else {
		const [header, payload, signature] = jwt.trim().split('.');

		if (typeof header === 'string' && typeof payload === 'string' && typeof signature === 'string') {
			const decoder = new TextDecoder('utf-8');

			return {
				header: JSON.parse(decoder.decode(Uint8Array.fromBase64(header, { alphabet }))),
				payload: JSON.parse(decoder.decode(Uint8Array.fromBase64(payload, { alphabet }))),
				signature: Uint8Array.fromBase64(signature, { alphabet }),
				data: new TextEncoder().encode(`${header}.${payload}`),
			};
		} else {
			return null;
		}
	}
}

/**
 * Verifies and decodes a JSON Web Token (JWT).
 *
 * @param {string} jwt - The JWT to verify and decode.
 * @param {CryptoKey | CryptoKeyPair} key - The key or key pair used to verify the JWT signature.
 * @param {Object} options - Optional options for verification.
 * @param {number} options.leeway - The allowed clock skew in seconds (default: 60).
 * @returns {Promise<object | null>} A Promise that resolves to an object containing the decoded header, payload, signature, and raw data if the JWT is valid, or `null` if the JWT is invalid.
 */
export async function verifyJWT(jwt, key, { leeway = 60 } = {}) {
	if (typeof jwt !== 'string') {
		throw new TypeError('JWT must be a token/string.');
	} else if (key instanceof CryptoKey) {
		const { header, payload, signature, data } = decodeToken(jwt) ?? {};

		if (! verifyHeader(header)) {
			return null;
		} else if (! verifyPayload(payload, leeway)) {
			return null;
		} else if (! await crypto.subtle.verify(
			ALGOS[header.alg],
			key,
			signature,
			data,
		).catch(() => false)) {
			return null;
		} else {
			return payload;
		}
	} else if (key?.publicKey instanceof CryptoKey) {
		return await verifyJWT(jwt, key.publicKey);
	} else {
		throw new TypeError('Key must be either a CryptoKey or CryptoKeyPair.');
	}
}


/**
 * Extracts the request token from the Authorization header of a request.
 *
 * @param {Request} req - The HTTP request object.
 * @returns {string | null} The request token if found, or null if not found.
 * @throws {TypeError} - If the provided object is not a Request object.
 */
export function getRequestToken(req) {
	if (! (req instanceof Request)) {
		throw new TypeError('Not a request object.');
	} else if (! req.headers.has(AUTH)) {
		return null;
	} else {
		const token = req.headers.get(AUTH);
		// Strips off the "Bearer" and the space
		return token.startsWith('Bearer ') ? token.substring(7) : null;
	}
}

/**
 * Decodes the request token from the Authorization header.
 *
 * @param {Request} req - The HTTP request object.
 * @returns {Object | null} The decoded token object if valid, null otherwise.
 * @throws {TypeError} - If the provided object is not a Request object.
 */
export function decodeRequestToken(req) {
	const token = getRequestToken(req);
	return typeof token === 'string' ? decodeToken(token) : null;
}
