import { ALPHABET as alphabet, ALGOS, AUTH } from './consts.js';
import { findKeyAlgo, getKeyId } from './utils.js';

/**
 * Generates a JSON Web Token (JWT) using the provided payload and private key.
 *
 * @param {Object} payload - The payload data to include in the JWT.
 * @param {CryptoKey} privateKey - The private key used to sign the JWT.
 * @returns {Promise<string>} A promise that resolves to the generated JWT.
 * @throws {Error} - If there's an error generating the JWT.
 */
export async function createJWT(payload, privateKey) {
	const encoder = new TextEncoder();
	const [name, algo] = findKeyAlgo(privateKey);

	const encodedHeader = encoder.encode(JSON.stringify({ alg: name, kid: await getKeyId(privateKey), typ: 'JWT' })).toBase64({ alphabet });
	const encodedPayload = encoder.encode(JSON.stringify(payload)).toBase64({ alphabet });
	const signature = await crypto.subtle.sign(
		{ ...algo, ...privateKey.algorithm },
		privateKey,
		encoder.encode(`${encodedHeader}.${encodedPayload}`)
	);

	return `${encodedHeader}.${encodedPayload}.${new Uint8Array(signature).toBase64({ alphabet })}`;
}


/**
 * Decodes a JSON Web Token (JWT) into its constituent parts.
 *
 * @param {string} jwt - The JWT to decode.
 * @returns {{ header: object, payload: object, signature: Uint8Array, data: Uint8Array }} An object containing the decoded header, payload, signature, and raw data.
 * @throws {Error} - If the JWT is malformed or cannot be decoded.
 */
export function decodeToken(jwt) {
	const [header, payload, signature] = jwt.split('.');
	const decoder = new TextDecoder('utf-8');

	return {
		header: JSON.parse(decoder.decode(Uint8Array.fromBase64(header, { alphabet }))),
		payload: JSON.parse(decoder.decode(Uint8Array.fromBase64(payload, { alphabet }))),
		signature: Uint8Array.fromBase64(signature, { alphabet }),
		data: new TextEncoder().encode(`${header}.${payload}`),
	};
}

/**
 * Decodes a JSON Web Token (JWT) into its individual components.
 *
 * @param {string} jwt - The JWT to decode.
 * @returns {Object} An object containing the decoded header, payload, signature, and raw data.
 * @throws {Error} - If the JWT is malformed or cannot be decoded.
 */
export async function verifyJWT(jwt, publicKey) {
	const { header, payload, signature, data } = decodeToken(jwt);
	const now = Math.round(Date.now() / 1000);

	if (! await crypto.subtle.verify(
		ALGOS[header.alg],
		publicKey,
		signature,
		data,
	).catch(() => false)) {
		console.warn('Bad signature.');
		return null;
	} else if (
		(typeof payload.nbf === 'number' && payload.nbf > now)
		|| (typeof payload.exp === 'number' && payload.exp < now)
	) {
		console.warn('Bad times.');
		return null;
	} else {
		return payload;
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
