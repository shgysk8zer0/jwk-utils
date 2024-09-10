import { AUTH } from './consts.js';
import { decodeRequestToken, createJWT, verifyJWT, verifySignature } from './jwt.js';
import { isOrigin } from './utils.js';

const TTL = 60;

const getId = (length = 8) => crypto.getRandomValues(new Uint8Array(length)).toHex();

/**
 * Creates an origin authentication token (OAT) for a given origin.
 *
 * @param {string} origin - The origin to be authenticated.
 * @param {CryptoKey | CryptoKeyPair} key - The private key or key pair used to sign the JWT.
 * @param {object} [options] - Optional options for the token creation.
 * @param {number} [options.ttl=60] - The time-to-live (TTL) for the token in seconds.
 * @param {string} [options.id=crypto.randomUUID()] - A unique identifier for the token.
 * @param {Date} [options.issued=new Date()] - The issued-at time for the token.
 * @param {string} [options.subject] - Optional subject (sub) for the JWT.
 * @param {string} [options.audience] - Optional audience (aud) for the JWT.
 * @param {string} [options.roles=''] - Role/roles for which the origin token operates
 * @param {string[]} [options.entitlements=[]] - Entitlements/permissions the stateless origin token grants.
 * @param {string | null} [options.scope=null] - Scope for the Stateless origin token.
 * @param {...any} [options] - Any additional data to include in the payload.
 * @returns {Promise<string | Error>} A promise that resolves to the generated OAT or any error given.
 * @throws {TypeError} - If the origin is not a valid string or URL.
 */
export async function createOriginAuthToken(origin, key, {
	ttl = TTL,
	id: jti = getId(),
	issued = new Date(),
	subject: sub,
	audience: aud,
	roles = '',
	entitlements = [],
	scope = null,
	...rest
} = {}) {
	if (! isOrigin(origin)) {
		throw new TypeError('Origin must be a valid origin.');
	} else if (URL.parse(origin)?.origin !== origin) {
		throw new TypeError(`${origin} is not a valid origin.`);
	} else {
		const issuedAt = Math.floor(issued.getTime() / 1000);

		return await createJWT({
			iss: origin,
			iat: issuedAt,
			nbf: issuedAt,
			exp: issuedAt + ttl,
			jti, sub, aud, roles, entitlements, scope, ...rest,
		}, key);
	}
}


/**
 * Authenticates a request by generating a JWT and setting the Authorization header.
 *
 * @param {Request} req - The HTTP request object to authenticate.
 * @param {CryptoKey | CryptoKeyPair} key - The private key used to sign the JWT.
 * @param {object} [options] - Optional options for the authentication process.
 * @param {number} [options.ttl=60] - The time-to-live (TTL) for the token in seconds.
 * @param {string} [options.id=crypto.randomUUID()] - A unique identifier for the token.
 * @param {Date} [options.issued=new Date()] - The issued-at time for the token.
 * @param {string} [options.subject] - Optional subject (sub) for the JWT.
 * @param {string} [options.audience] - Optional audience (aud) for the JWT.
 * @param {...any} [options] - Any additional data to include in the payload.
 * @returns {Promise<Request>} A promise that resolves to the authenticated request object.
 * @throws {Error} - If there's an error generating the JWT or setting the header.
 */
export async function authenticateRequest(req, key, {
	ttl = TTL,
	id = getId(),
	issued = new Date(),
	subject,
	audience,
	...rest
} = {}) {
	const token = await createOriginAuthToken(req.headers.get('Origin'), key, {
		ttl, id, issued, subject, audience, ...rest
	});

	req.headers.set(AUTH, `Bearer ${token}`);

	return req;
}

/**
 * Decodes and validates an origin authentication token (OAT).
 *
 * @param {string} token - The OAT to decode and verify.
 * @param {CryptoKey | CryptoKeyPair} key - The key or key pair used for verification.
 * @returns {Promise<object | Error>} A promise that resolves to the decoded payload or any error given in decoding/verifying.
 *                                  if the OAT is valid, or null otherwise.
 * @throws {TypeError} - If `key` is not a `CryptoKey` or `CryptoKeyPair`.
 */
export async function decodeOriginToken(token, origin, key) {
	const payload = await verifyJWT(token, key);

	if (payload instanceof Error) {
		return payload;
	} else if (typeof payload !== 'object' || payload === null) {
		return new Error('Invalid token could not be parsed.');
	} else if (typeof origin !== 'string' || origin.length === 0) {
		return new TypeError('Origin is required to be a string.');
	} else if (! ['iss', 'iat', 'exp', 'nbf'].every(key => key in payload)) {
		return new Error('Payload missing required fields.');
	} else if (typeof payload.iss !== 'string' || ! URL.parse(payload.iss)?.origin === payload.origin) {
		return new Error(`Invalid issuer (iss): ${payload.iss}`);
	} else if (payload.iss !== origin) {
		return new Error('Payload issuer does not match the expected origin.');
	} else {
		return payload;
	}
}

/**
 * Decodes and validates the request token from the Authorization header.
 *
 * @param {Request} req - The HTTP request object.
 * @returns {Promise<object | Error>} A promise that resolves to the validated payload object if valid, an Error of what failed otherwise.
 * @throws {TypeError} - If the provided object is not a Request object or if mandatory headers are missing.
 */
export async function decodeRequestOriginToken(req, key, { entitlements = [] } = {}) {
	if (! (req instanceof Request)) {
		throw new TypeError('Not a request object.');
	} else if(! req.headers.has('Origin')) {
		return new TypeError('Headers is missing required Origin.');
	} else {
		const now = Math.round(Date.now() / 1000);
		const result = decodeRequestToken(req);

		if (result instanceof Error) {
			return result;
		} else if (typeof result?.payload !== 'object') {
			return new TypeError('Invalid payload in token.');
		} else if (! ['alg', 'kid'].every(prop => prop in result.header)) {
			return new Error('Invalid token header.');
		} else if (! ['sub', 'iat', 'exp', 'nbf', 'jti', 'entitlements', 'scope'].every(key => key in result.payload)) {
			return new TypeError('Invalid payload of token.');
		} else if (typeof result.payload.nbf !== 'number' || typeof result.payload.exp !== 'number' || now < result.payload.nbf || result.payload.exp < now) {
			return new Error('Token is expired or invalid.');
		} else if (! (Array.isArray(result.payload.entitlements) && entitlements.every(perm => result.payload.entitlements.includes(perm)))) {
			return new Error('Token is valid but does not have necessary entitlements/permissions.');
		} else  if (!await verifySignature(result, key)) {
			return new Error('Token signature did not validate.');
		} else {
			return result.payload;
		}
	}
}
