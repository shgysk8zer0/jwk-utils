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
	return (typ === 'JWT' && typeof alg === 'string' && (alg === 'none' || alg in ALGOS));
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

		if (! key.usages.includes('sign')) {
			throw new TypeError('Key usages do not include "sign".');
		} else if (typeof name === 'string') {
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
			return new Error('Invalid or unsuppported algorithm.');
		}
	} else if (typeof key === 'object' && key !== null && key.privateKey instanceof CryptoKey) {
		return await createJWT(payload, key.privateKey);
	} else {
		throw new TypeError('Key must be either a CryptoKey or CrpytoKeyPair.');
	}
}

/**
 * Generates a JSON Web Token (JWT) using the provided payload and private key.
 *
 * @param {Object} payload - The payload data to include in the JWT.
 * @returns {string}} The generated unsecure (unsigend) JWT.
 */
export function createUnsecuredJWT(payload) {
	const encoder = new TextEncoder();

	const header = encoder.encode(JSON.stringify({ alg: 'none', typ: 'JWT' })).toBase64({ alphabet }).replaceAll('=', '');
	const encodedPayload = encoder.encode(JSON.stringify(payload)).toBase64({ alphabet }).replaceAll('=', '');
	return `${header}.${encodedPayload}.`;
}


/**
 * Decodes a JSON Web Token (JWT) into its constituent parts.
 *
 * @param {string} jwt - The JWT to decode.
 * @returns {{ header: object, payload: object, signature: Uint8Array, data: Uint8Array } | Error} An object containing the decoded header, payload, signature, and raw data or any error that occured in parsing the token.
 * @throws {Error} - If the JWT is malformed or cannot be decoded.
 */
export function decodeToken(jwt) {
	if (typeof jwt !== 'string') {
		throw new TypeError('JWT is not a string.');
	} else {
		const [header, payload, signature] = jwt.trim().split('.');

		if (typeof header === 'string' && typeof payload === 'string' && typeof signature === 'string') {
			try {
				const decoder = new TextDecoder('utf-8');
				const decodedHeader = JSON.parse(decoder.decode(Uint8Array.fromBase64(header, { alphabet })));
				const decodedPayload = JSON.parse(decoder.decode(Uint8Array.fromBase64(payload, { alphabet })));

				if (! (verifyHeader(decodedHeader))) {
					return new Error('Invalid JWT header.');
				} else if (decodedHeader.alg === 'none' && signature.length === 0) {
					const uint = new Uint8Array();

					return {
						header: decodedHeader,
						payload: decodedPayload,
						signature: uint,
						data: uint,
					};
				} else {
					return {
						header: decodedHeader,
						payload: decodedPayload,
						signature: Uint8Array.fromBase64(signature, { alphabet }),
						data: new TextEncoder().encode(`${header}.${payload}`),
					};
				}

			} catch(err) {
				return err;
			}
		} else {
			return new Error('Unable to decode JWT.');
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
 * @returns {Promise<object | Error>} A Promise that resolves to an object containing the decoded header, payload, signature, and raw data if the JWT is valid, or an Error if the JWT is invalid.
 * @throws {TypeError} If the given `key` is not a `CryptoKey` or `CryptoKeyPair` with a publicKey.
 */
export async function verifyJWT(jwt, key, { leeway = 60 } = {}) {
	if (typeof jwt !== 'string') {
		throw new TypeError('JWT must be a token/string.');
	} else if (key instanceof CryptoKey) {
		const decoded = decodeToken(jwt) ?? {};

		if (! key.usages.includes('verify')) {
			throw new TypeError('Key permissions do not include "verify".');
		} else if (decoded instanceof Error) {
			return decoded;
		} else if (! verifyHeader(decoded.header)) {
			return new Error('Invalid header for JWT.');
		} else if (! verifyPayload(decoded.payload, leeway)) {
			return new Error('Invalid payload for JWT.');
		} else if (decoded.header.alg === 'none') {
			return new TypeError('JWT is a valid but unsecured token.');
		} else if (! await crypto.subtle.verify(
			ALGOS[decoded.header.alg],
			key,
			decoded.signature,
			decoded.data,
		).catch(() => false)) {
			return new Error('Unable to verify JWT signature.');
		} else {
			return decoded.payload;
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
 * @returns {string | null} The request token if found, null if Authorization header is missing or invalid.
 * @throws {TypeError} - If the provided object is not a Request object.
 */
export function getRequestToken(req) {
	if (! (req instanceof Request)) {
		throw new TypeError('Not a request object.');
	} else if (req.headers.has(AUTH)) {
		const token = req.headers.get(AUTH);
		// Strips off the "Bearer" and the space
		return token.startsWith('Bearer ') ? token.substring(7) : null;
	} else {
		const url = URL.parse(req.url);

		return url instanceof URL ? url.searchParams.get('token') : null;
	}
}

/**
 * Decodes the request token from the Authorization header or token param.
 *
 * @param {Request} req - The HTTP request object.
 * @returns {Object | Error} The decoded token object if valid, Error if there was a problem decoding the token.
 * @throws {TypeError} - If the provided object is not a Request object.
 */
export function decodeRequestToken(req) {
	const token = getRequestToken(req);
	return typeof token === 'string' ? decodeToken(token) : token;
}

/**
 * Decodes and verifies the request token from the Authorization header or `token` param.
 *
 * @param {Request} req - The HTTP request object.
 * @param {CryptoKey | CryptoKeyPair} key - The key or key pair used to verify the JWT signature.
 * @param {Object} options - Optional options for verification.
 * @param {number} options.leeway - The allowed clock skew in seconds (default: 60).
 * @returns {Object | Error} The decoded token payload if valid, Error if there was a problem decoding the token.
 * @throws {TypeError} - If the provided object is not a Request object.
 */
export function verifyRequestToken(req, key, { leeway = 60 } = {}) {
	const token = getRequestToken(req);
	return typeof token === 'string' ? verifyJWT(token, key, { leeway }) : token;
}
