import { ALPHABET as alphabet, ALGOS, AUTH, LEEWAY } from './consts.js';
import { findKeyAlgo, getKeyId } from './utils.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8');

/**
 * Gets the key valid for signing from a `CryptoKey` or `CryptoKeyPair`.
 *
 * @param {CryptoKey | CryptoKeyPair} keys - Key or key pair to find signing key in.
 * @returns {CryptoKey | Error} CryptoKey with "sign" usage if found or error if not found.
 */
export function getSigningKey(keys) {
	if (keys instanceof CryptoKey && keys.usages.includes('sign')) {
		return keys;
	} else if (keys?.privateKey instanceof CryptoKey && keys.privateKey.usages.includes('sign')) {
		return keys.privateKey;
	} else {
		return new Error('No signing key available.');
	}
}

/**
 * Gets the key valid for verifying from a `CryptoKey` or `CryptoKeyPair`.
 *
 * @param {CryptoKey | CryptoKeyPair} keys - Key or key pair to find verifying key in.
 * @returns {CryptoKey | Error} CryptoKey with "verify" usage if found or error if not found.
 */
export function getVerifyingKey(keys) {
	if (keys instanceof CryptoKey && keys.usages.includes('verify')) {
		return keys;
	} else if (keys?.publicKey instanceof CryptoKey && keys.publicKey.usages.includes('verify')) {
		return keys.publicKey;
	} else {
		return new Error('No verifying key available.');
	}
}

/**
 * Verifies the header of a JSON Web Token (JWT).
 *
 * @param {object} options - An object containing the header properties.
 * @param {string} options.typ - The token type, expected to be 'JWT'.
 * @param {string} options.alg - The algorithm used to sign the token, must be a string and a known algorithm (from ALGOS) or "none".
 * @returns {boolean} True if the header is valid, false otherwise.
 */
export function verifyHeader({ typ, alg } = {}) {
	return (typ === 'JWT' && typeof alg === 'string' && (alg === 'none' || alg in ALGOS));
}

/**
 * Checks if the payload of a token meets given requirements.
 *
 * @param {object} payload - The payload object to be verified.
 * @param {object} [options] - Optional options for verification.
 * @param {number} [options.leeway=60] (optional) - Number of seconds allowed for clock skew, defaults to 60.
 * @param {string[]} [options.entitlements=[]] - Entitlements/permissions required.
 * @param {string[]} [options.roles=[]] - Require user have one or more roles
 * @param {string[]} [options.claims=[]] - Required/expected claims in a payload object.
 * @param {string|null} [options.owner=null] - Optional owner value to bypass permissions for a resource
 * @param {string} [options.ownerClaim='sub'] - Optional claim to identify the owner of a resource
 * @param {string[]} [claims=[]] - Expected claims for the payload.
 * @returns {boolean} True if the payload is valid, false otherwise.
 */
export function isVerifiedPayload(payload, {
	leeway = LEEWAY,
	entitlements = [],
	roles = [],
	claims = [],
	owner = null,
	ownerClaim = 'sub',
	...checks
} = {}) {
	return ! (verifyPayload(payload, { leeway, entitlements, roles, claims, owner, ownerClaim, ...checks }) instanceof Error);
}

/**
 * Checks if the payload of a decoded token includes given `entitlements`.
 *
 * @param {{ entitlements: string[] }} payload - The payload object decoded from a JWT
 * @param {string[]} [entitlements=[]] - The entitlements/permissions to check for.
 * @returns {boolean} Whether or not the parsed token payload has all given `entitelments`.
 */
export function hasEntitlements(payload, entitlements = []) {
	return entitlements.length === 0 || (Array.isArray(payload?.entitlements) && entitlements.every(ent => payload.entitlements.includes(ent)));
}

/**
 * Verifies the signature of a decoded JWT
 *
 * @param {object} decoded - The decoded JWT contents.
 * @param {object} decoded.header - The header of the decoded JWT.
 * @param {Uint8Array} decoded.signature - The deocded signature of the JWT.
 * @param {Uint8Array} decoded.data - The decoded data (header & payload) of the JWT.
 * @param {CryptoKey} key - The key to verify the signature.
 * @returns {Promise<boolean>} Whether or not the signature was verified.
 * @throws {TypeError} If the key is not a CryptoKey or if it lacks "verify" in usages.
 */
export async function verifySignature({ header, signature, data }, key) {
	if (! (key instanceof CryptoKey)) {
		throw new TypeError('Verifying signatures requires a `CryptoKey`.');
	} else if (! key.usages.includes('verify')) {
		throw new TypeError('Key does not include "verify" in usages.');
	} else {
		return await crypto.subtle.verify(
			ALGOS[header?.alg],
			key,
			signature,
			data,
		).catch(() => false);
	}
}

/**
 * Generates a JSON Web Token (JWT) using the provided payload and private key.
 *
 * @param {object} payload - The payload data to include in the JWT.
 * @param {CryptoKey | CryptoKeyPair} key - The private/secret key or key pair used to sign the JWT.
 * @returns {Promise<string>} A promise that resolves to the generated JWT.
 * @throws {TypeError} If the key is not a CryptoKey/CryptoKeyPair or if it lacks "sign" in usages.
 * @throws {Error} If there's an error generating the JWT.
 */
export async function createJWT(payload, key) {
	const signingKey = getSigningKey(key);

	if (signingKey instanceof Error) {
		return signingKey;
	} else if (signingKey instanceof CryptoKey) {
		const [name, algo] = findKeyAlgo(key);

		if (! key.usages.includes('sign')) {
			throw new TypeError('Key usages do not include "sign".');
		} else if (typeof name === 'string') {
			const encodedHeader = encoder.encode(JSON.stringify({ alg: name, kid: await getKeyId(key), typ: 'JWT' })).toBase64({ alphabet }).replaceAll('=', '');
			const encodedPayload = encoder.encode(JSON.stringify(payload)).toBase64({ alphabet }).replaceAll('=', '');
			const signature = await crypto.subtle.sign(
				{ ...algo, ...key.algorithm },
				key,
				encoder.encode(`${encodedHeader}.${encodedPayload}`)
			);

			return `${encodedHeader}.${encodedPayload}.${new Uint8Array(signature).toBase64({ alphabet }).replaceAll('=', '')}`;
		} else {
			return new Error('Invalid or unsupported algorithm.');
		}
	}
}

/**
 * Refreshes a JWT by validating the existing token, updating the issued time and expiration,
 * and re-signing it using the provided keys.
 *
 * @param {string} token - The existing JWT to be refreshed.
 * @param {CryptoKey | CryptoKeyPair} keys - The key or key pair used for signing and verifying the JWT.
 * @param {Object} [options] - Optional parameters.
 * @param {Date} [options.issued=new Date()] - The date when the new token is issued (used for the `iat` claim).
 * @param {number} [options.ttl=60] - Time-to-live for the token, in seconds, used to set the `exp` claim.
 *
 * @returns {Promise<string|Error>} Returns the refreshed JWT as a string or an Error if something goes wrong.
 */
export async function refreshJWT(token, keys, { issued = new Date(), ttl = 60 } = {}) {
	const signingKey = getSigningKey(keys);
	const verifyingKey = getVerifyingKey(keys);
	const decoded = decodeToken(token);
	const [name, algo] = findKeyAlgo(signingKey);

	if (signingKey instanceof Error) {
		return signingKey;
	} else if (verifyingKey instanceof Error) {
		return verifyingKey;
	} else if (typeof name !== 'string') {
		return new Error('Could not find algorithm for signing key.');
	} else if (! (issued instanceof Date && ! Number.isNaN(issued.getTime()))) {
		return new Error('Invalid issued/`iat` for new token.');
	} else if (decoded instanceof Error) {
		return decoded;
	} else if (! verifyHeader(decoded?.header)) {
		return new Error('Error verifying decoded token header.');
	} else if (! isVerifiedPayload(decoded?.payload, { leeway: 60, claims: ['iat', 'exp'] })) {
		return new Error('Error verifying decoded token payload.');
	} else if (! ['iat', 'exp'].every(claim => claim in decoded.payload)) {
		return new Error('Cannot renew a token without `iat` and `exp`.');
	} else if (! (decoded.signature instanceof Uint8Array)) {
		return new Error('Missing or invalid token signature.');
	} else if (! await verifySignature(decoded, verifyingKey)) {
		return new Error('Could not verify token signature.');
	} else {
		const iat = Math.floor(issued.getTime() / 1000);
		decoded.payload.iat = iat;
		decoded.payload.exp = iat + ttl;
		const header = encoder.encode(JSON.stringify(decoded.header)).toBase64({ alphabet }).replaceAll('=', '');
		const payload = encoder.encode(JSON.stringify(decoded.payload)).toBase64({ alphabet }).replaceAll('=', '');
		const signature = await crypto.subtle.sign(
			{ ...algo, ...signingKey.algorithm },
			signingKey,
			encoder.encode(`${header}.${payload}`)
		);

		return `${header}.${payload}.${new Uint8Array(signature).toBase64({ alphabet }).replaceAll('=', '')}`;
	}
}

/**
 * Generates a JSON Web Token (JWT) using the provided payload and private key.
 *
 * @param {object} payload - The payload data to include in the JWT.
 * @returns {string} The generated unsecure (unsigend) JWT.
 */
export function createUnsecuredJWT(payload) {
	const header = encoder.encode(JSON.stringify({ alg: 'none', typ: 'JWT' })).toBase64({ alphabet }).replaceAll('=', '');
	const encodedPayload = encoder.encode(JSON.stringify(payload)).toBase64({ alphabet }).replaceAll('=', '');
	return `${header}.${encodedPayload}.`;
}

/**
 * Decodes a JSON Web Token (JWT) into its constituent parts.
 *
 * @param {string} jwt - The JWT to decode.
 * @returns {{ header: object, payload: object, signature: Uint8Array, data: Uint8Array } | Error} An object containing the decoded header, payload, signature, and raw data or any error that occured in parsing the token.
 * @throws {TypeError} If the JWT is not a string.
 */
export function decodeToken(jwt) {
	if (typeof jwt !== 'string') {
		throw new TypeError('JWT is not a string.');
	} else {
		const [header, payload, signature] = jwt.trim().split('.');

		if (typeof header === 'string' && typeof payload === 'string' && typeof signature === 'string') {
			try {
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
 *
 * @param {object} claims
 * @param {object} payload
 * @returns {boolean}
 */
function _checkClaims(claims, payload = {}) {
	const entries = Object.entries(claims);

	return entries.length === 0 || entries.every(([key, value]) => {
		if (! payload.hasOwnProperty(key)) {
			return false;
		} else if (typeof value === 'function') {
			return value.call(payload, value);
		} else if (typeof value !== typeof payload[key]) {
			return false;
		} else if (value === payload[key]) {
			return true;
		} else {
			switch(typeof value) {
				case 'string':
				case 'number':
				case 'bigint':
				case 'undefined':
					return false; // Already know they are not equal

				case 'object':
					if (Array.isArray(value)) {
						return value.every(item => payload[key].includes(item));
					} else if (value === null) {
						return false;
					} else {
						return Object.entries(value).every(([k, v]) => payload[key][k] === v);
					}

				default:
					return false; // What's left? Symbols? Those are not allowed.
			}
		}
	});
}

/**
 *
 * @param {string[]} roles
 * @param {object} payload
 * @returns {boolean}
 */
function _checkRoles(roles, payload) {
	if (! Array.isArray(payload.roles)) {
		return false;
	} else {
		return roles.some(role => payload.roles.includes(role));
	}
}

/**
 * Verifies and decodes a JSON Web Token (JWT).
 *
 * @param {string} jwt - The JWT to verify and decode.
 * @param {CryptoKey|CryptoKeyPair} key - The key or key pair used to verify the JWT signature.
 * @param {object} [options] - Optional options for verification.
 * @param {number} [options.leeway=60] - The allowed clock skew in seconds (default: 60).
 * @param {string[]} [options.entitlements=[]] - Entitlements/permissions required.
 * @param {string[]} [options.roles=[]] - Require user have one or more roles
 * @param {string[]} [options.claims=[]] - Required/expected claims in a payload object.
 * @param {string|null} [options.owner=null] - Optional owner value to bypass permissions for a resource
 * @param {string} [options.ownerClaim='sub'] - Optional claim to identify the owner of a resource
 * @returns {Promise<object|Error>} A Promise that resolves to an object containing the decoded header, payload, signature, and raw data if the JWT is valid, or an Error if the JWT is invalid.
 * @throws {TypeError} If the given `key` is not a `CryptoKey` or `CryptoKeyPair` with a publicKey.
 */
export async function verifyJWT(jwt, key, {
	leeway = LEEWAY,
	entitlements = [],
	roles = [],
	claims = [],
	owner = null,
	ownerClaim = 'sub',
	...checks
} = {}) {
	const verifyingKey = getVerifyingKey(key);

	if (typeof jwt !== 'string') {
		throw new TypeError('JWT must be a token/string.');
	} else if (verifyingKey instanceof Error) {
		throw verifyingKey;
	} else if (verifyingKey instanceof CryptoKey) {
		const decoded = decodeToken(jwt);
		const err = decoded instanceof Error ? decoded : verifyPayload(decoded.payload, {
			leeway, claims, entitlements, roles, owner, ownerClaim, ...checks,
		});

		if (err instanceof Error) {
			return err;
		} else if (decoded.header.alg === 'none') {
			return new TypeError('JWT is a valid but unsecured token.');
		} else if (! await verifySignature(decoded, key)) {
			return new Error('Unable to verify JWT signature.');
		} else {
			return decoded.payload;
		}
	} else {
		throw new TypeError('Key must be either a CryptoKey or CryptoKeyPair.');
	}
}

/**
 * Verifies the payload of a JWT, returning any errors
 *
 * @param {object} payload
 * @param {object} [options] - Optional options for verification.
 * @param {number} [options.leeway=60] - The allowed clock skew in seconds (default: 60).
 * @param {string[]} [options.entitlements=[]] - Entitlements/permissions required.
 * @param {string[]} [options.roles=[]] - Require user have one or more roles
 * @param {string[]} [options.claims=[]] - Required/expected claims in a payload object.
 * @param {string|null} [options.owner=null] - Optional owner value to bypass permissions for a resource
 * @param {string} [options.ownerClaim='sub'] - Optional claim to identify the owner of a resource
 * @returns {Error|void} - Any error in verifying the payload, or `undefined` if none
 */
export function verifyPayload(payload, {
	leeway = LEEWAY,
	entitlements = [],
	roles = [],
	claims = [],
	owner = null,
	ownerClaim = 'sub',
	...checks
} = {}) {
	const isOwner = typeof owner === 'string' && typeof payload === 'object' && payload[ownerClaim] === owner;
	const now = Math.floor(Date.now() / 1000);

	if (typeof payload !== 'object' || payload === null) {
		return new Error('Payload is not an object.');
	} else if (typeof payload.iat === 'number' && ! Number.isNaN(payload.iat) && now < (payload.iat - leeway)) {
		return new Error('Token issued at is invalid.');
	} else if (typeof payload.nbf === 'number' && ! Number.isNaN(payload.nbf) && now < (payload.nbf - leeway)) {
		return new Error('Token is not yet valid.');
	} else if (typeof payload.exp === 'number' && ! Number.isNaN(payload.exp) && now > (payload.exp + leeway)) {
		return Error('Token is invlalid');
	} else if (claims.length !== 0 && ! claims.every(claim => claim in payload)) {
		return new Error('Explected claims were not made by token.');
	} else if (! _checkClaims(checks, payload)) {
		return new Error('JWT did not pass constraint checks.');
	} else if (isOwner || _checkRoles(roles, payload)) {
		return undefined;
	} else if (! hasEntitlements(payload, entitlements)) {
		return new Error('JWT does not have required permissions.');
	}
}

/**
 * Extracts the request token from the Authorization header of a request.
 *
 * @param {Request} req - The HTTP request object.
 * @returns {string | null} The request token if found, null if Authorization header is missing or invalid.
 * @throws {TypeError} If the provided object is not a Request object.
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
 * @param {object} [options] - Optional options for verification.
 * @param {number} [options.leeway] - The allowed clock skew in seconds (default: 60).
 * @param {string[]} [options.claims=[]] - Required/expected claims in a payload object.
 * @returns {object | Error} The decoded token object if valid, Error if there was a problem decoding the token.
 * @throws {TypeError} If the provided object is not a Request object.
 */
export function decodeRequestToken(req, { claims = [], leeway = LEEWAY } = {}) {
	const token = getRequestToken(req);
	return typeof token === 'string' ? decodeToken(token, { claims, leeway }) : token;
}

/**
 * Decodes and verifies the request token from the Authorization header or `token` param.
 *
 * @param {Request} req - The HTTP request object.
 * @param {CryptoKey | CryptoKeyPair} key - The key or key pair used to verify the JWT signature.
 * @param {object} [options] - Optional options for verification.
 * @param {number} [options.leeway] - The allowed clock skew in seconds (default: 60).
 * @param {string[]} [options.claims=[]] - Required/expected claims in a payload object.
 * @param {string[]} [options.entitlements=[]] - Entitlements/permissions required.
 * @returns {Promise<object | Error>} The decoded token payload if valid, Error if there was a problem decoding the token.
 * @throws {TypeError} If the provided object is not a Request object.
 */
export async function verifyRequestToken(req, key, { leeway = LEEWAY, claims = [], entitlements = [] } = {}) {
	const token = getRequestToken(req);
	return typeof token === 'string' ? await verifyJWT(token, key, { leeway, claims, entitlements }) : token;
}
