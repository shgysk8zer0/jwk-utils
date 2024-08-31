export const AUTH = 'Authentication';
export const ALPHABET = 'base64url';
export const MIME_TYPE = 'application/jwk+json';
export const DEFAULT_ALGO = 'ES256';
/**
 * A mapping of algorithm names to their corresponding cryptographic parameters.
 *
 * @type {Object}
 * @property {Object} ES256 - Configuration for the Elliptic Curve Digital Signature Algorithm (ECDSA) using the P-256 curve and SHA-256 hash.
 * @property {Object} RS256 - Configuration for the RSA Signature Algorithm (RSASSA-PKCS1-v1_5) using SHA-256 hash, a modulus length of 2048 bits, and a public exponent of 0x010001.
 */
export const ALGOS = {
	ES256: {
		name: 'ECDSA',
		namedCurve: 'P-256',
		hash: 'SHA-256',
	},
	RS256: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: 'SHA-256',
		modulusLength: 2048,
		publicExponent: new Uint8Array([1, 0, 1]),
	},
	HS256: {
		name: 'HMAC',
		hash: 'SHA-256',
	},
};
