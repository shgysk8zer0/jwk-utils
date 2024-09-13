import { AUTH, LEEWAY } from './consts.js';
import { createJWT, verifyJWT, getRequestToken } from './jwt.js';
import { isOrigin } from './utils.js';

const TTL = 60;

const EXPECTED_CLAIMS = ['iat', 'exp', 'nbf', 'jti', 'entitlements', 'scope'];

/**
 * Creates a random hex string of a given number of bytes.
 *
 * @param {number} [length=8] - Number of bytes.
 * @returns {string} A random hex string.
 */
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
 * @throws {TypeError} If the origin is not a valid string or URL.
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
 * @throws {Error} If there's an error generating the JWT or setting the header.
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
 * @param {string} origin - The origin of the request/token
 * @param {CryptoKey | CryptoKeyPair} key - The key or key pair used for verification.
 * @param {object} options - Optional options for verification.
 * @param {number} [options.leeway] - The allowed clock skew in seconds (default: 60).
 * @param {string[]} [options.entitlements] - Entitlements/permissions required.
 * @returns {Promise<object | Error>} A promise that resolves to the decoded payload or any error given in decoding/verifying.
 * @throws {TypeError} If `key` is not a `CryptoKey` or `CryptoKeyPair`.
 */
export async function verifyOriginToken(token, origin, key, { entitlements = [], leeway = LEEWAY } = {}) {
	const payload = await verifyJWT(token, key, { entitlements, leeway, claims: EXPECTED_CLAIMS });

	if (payload instanceof Error) {
		return payload;
	} else if (typeof payload !== 'object' || payload === null) {
		return new Error('Invalid token could not be parsed.');
	} else if (typeof origin !== 'string' || origin.length === 0) {
		return new TypeError('Origin is required to be a string.');
	} else if (typeof payload.iss !== 'string' || ! URL.parse(payload.iss)?.origin === origin) {
		return new Error(`Invalid issuer (iss): ${payload.iss}`);
	} else if (payload.iss !== origin) {
		return new Error(`Payload issuer does not match the expected origin: ${payload.iss}`);
	} else {
		return payload;
	}
}

/**
 * Decodes and validates the request token from the Authorization header or query string.
 *
 * @param {Request} req - The HTTP request object.
 * @param {CryptoKey | CryptoKeyPair} key - The key or key pair to verify the signature against.
 * @param {object} options - Optional options for verification.
 * @param {number} [options.leeway] - The allowed clock skew in seconds (default: 60).
 * @param {string[]} [options.entitlements] - Entitlements/permissions required.
 * @returns {Promise<object | Error>} A promise that resolves to the validated payload object if valid, an Error of what failed otherwise.
 * @throws {TypeError} If the provided object is not a Request object or if mandatory headers are missing.
 */
export async function verifyRequestOriginToken(req, key, { entitlements = [], leeway = LEEWAY } = {}) {
	if (! (req instanceof Request)) {
		throw new TypeError('Not a request object.');
	} else if(! req.headers.has('Origin')) {
		return new TypeError('Headers is missing required Origin.');
	} else {
		const token = getRequestToken(req);

		if (typeof token !== 'string') {
			return new Error('Request does not contain a JWT.');
		} else {
			return await verifyOriginToken(token, req.headers.get('Origin'), key, { entitlements, leeway });
		}
	}
}
