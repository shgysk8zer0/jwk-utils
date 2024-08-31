import { AUTH, ALGOS } from './consts.js';
import { decodeRequestToken, createJWT, verifyJWT } from './jwt.js';

/**
 * Creates an origin authentication token (OAT) for a given origin.
 *
 * @param {string} origin - The origin to be authenticated.
 * @param {CryptoKey} privateKey - The private key used to sign the JWT.
 * @param {Object} [options] - Optional options for the token creation.
 * @param {number} [options.ttl=60] - The time-to-live (TTL) for the token in seconds.
 * @param {string} [options.id=crypto.randomUUID()] - A unique identifier for the token.
 * @param {Date} [options.issued=new Date()] - The issued-at time for the token.
 * @param {number} [options.leeway=60] - The leeway in seconds to account for clock skew.
 * @returns {Promise<string>} A promise that resolves to the generated OAT.
 * @throws {TypeError} - If the origin is not a valid string or URL.
 */
export async function createOriginAuthToken(origin, privateKey, {
	ttl = 60,
	leeway = 60,
	id = crypto.getRandomValues(new Uint8Array(8)).toHex(),
	issued = new Date(),
} = {}) {
	if (typeof origin !== 'string' || origin.length === 0) {
		throw new TypeError('Origin must be a non-empty string.');
	} else if (URL.parse(origin)?.origin !== origin) {
		throw new TypeError(`${origin} is not a valid origin.`);
	} else {
		const issuedAt = Math.floor(issued.getTime() / 1000);

		return await createJWT({
			iss: origin,
			iat: issuedAt,
			nbf: issuedAt - leeway,
			exp: issuedAt + ttl,
			jti: id,
		}, privateKey);
	}
}


/**
 * Authenticates a request by generating a JWT and setting the Authorization header.
 *
 * @param {Request} req - The HTTP request object to authenticate.
 * @param {CryptoKey} privateKey - The private key used to sign the JWT.
 * @param {Object} [options] - Optional options for the authentication process.
 * @param {number} [options.ttl=60] - The time-to-live (TTL) for the token in seconds.
 * @param {string} [options.id=crypto.randomUUID()] - A unique identifier for the token.
 * @param {Date} [options.issued=new Date()] - The issued-at time for the token.
 * @param {number} [options.leeway=60] - The leeway in seconds to account for clock skew.
 * @returns {Promise<Request>} A promise that resolves to the authenticated request object.
 * @throws {Error} - If there's an error generating the JWT or setting the header.
 */
export async function authenticateRequest(req, privateKey, {
	ttl = 60,
	leeway = 60,
	id = crypto.getRandomValues(new Uint8Array(8)).toHex(),
	issued = new Date(),
} = {}) {
	const token = await createOriginAuthToken(req.headers.get('Origin'), privateKey, {
		ttl, leeway, id, issued,
	});

	req.headers.set(AUTH, `Bearer ${token}`);

	return req;
}

/**
 * Decodes and validates an origin authentication token (OAT).
 *
 * @param {string} token - The OAT to decode and verify.
 * @param {CryptoKey} publicKey - The public key used for verification.
 * @returns {Promise<Object>} A promise that resolves to the decoded payload
 *                                  if the OAT is valid, or null otherwise.
 * @throws {TypeError} - If the token is malformed or the payload is invalid.
 * @throws {Error} - If the JWT signature is invalid or the token is expired.
 */
export async function decodeOriginToken(token, origin, publicKey) {
	const payload = await verifyJWT(token, publicKey);

	if (typeof payload !== 'object' || payload === null) {
		return null;
	} else if (typeof origin !== 'string' || origin.length === 0) {
		return null;
	} else if (! ['iss', 'iat', 'exp', 'nbf'].every(key => key in payload)) {
		return null;
	} else if (typeof payload.iss !== 'string' || ! URL.parse(payload.iss)?.origin === payload.origin) {
		return null;
	} else if (payload.iss !== origin) {
		null;
	} else {
		return payload;
	}
}

/**
 * Decodes and validates the request token from the Authorization header.
 *
 * @param {Request} req - The HTTP request object.
 * @returns {Promise<Object | null>} A promise that resolves to the validated payload object if valid, null otherwise.
 * @throws {TypeError} - If the provided object is not a Request object or if mandatory headers are missing.
 * @throws {Error} - If the token is invalid (e.g., expired, malformed signature).
 */
export async function decodeRequestOriginToken(req, publicKey) {
	if (! (req instanceof Request)) {
		throw new TypeError('Not a request object.');
	} else if(! req.headers.has('Origin')) {
		throw new TypeError('Headers is missing required Origin.');
	} else {
		const now = Math.round(Date.now() / 1000);
		const { header, payload, signature, data } = decodeRequestToken(req);

		if (typeof payload !== 'object') {
			throw new TypeError('Invalid payload in token.');
		} else if (! ['alg', 'kid'].every(prop => prop in header)) {
			throw new Error('Invalid token header.');
		} else if (! ['sub', 'iat', 'exp', 'nbf'].every(key => key in payload)) {
			throw new TypeError('Invalid payload of token.');
		} else if (now < payload.nbf || payload.exp < now) {
			throw new Error('Token is expired or invalid.');
		} else  if (!await crypto.subtle.verify(
			ALGOS[header.alg],
			publicKey,
			signature,
			data,
		)) {
			throw new Error('Token signature did not validate.');
		} else {
			return payload;
		}
	}
}
