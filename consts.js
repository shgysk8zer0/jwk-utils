export const AUTH = 'Authorization';
export const ALPHABET = 'base64url';
export const MIME_TYPE = 'application/jwk+json';

export const ES256 = 'ES256';
export const ES384 = 'ES384';
export const ES512 = 'ES512';
export const RS256 = 'RS256';
export const RS384 = 'RS384';
export const RS512 = 'RS512';
export const DEFAULT_ALGO = ES256;

/**
 * A mapping of algorithm names to their corresponding cryptographic parameters.
 *
 * @type {Object}
 * @property {Object} ES256 - Configuration for the Elliptic Curve Digital Signature Algorithm (ECDSA) using the P-256 curve and SHA-256 hash.
 * @property {Object} ES384 - Configuration for the Elliptic Curve Digital Signature Algorithm (ECDSA) using the P-384 curve and SHA-384 hash.
 * @property {Object} ES512 - Configuration for the Elliptic Curve Digital Signature Algorithm (ECDSA) using the P-521 curve and SHA-512 hash.
 * @property {Object} RS256 - Configuration for the RSA Signature Algorithm (RSASSA-PKCS1-v1_5) using SHA-256 hash, a modulus length of 2048 bits, and a public exponent of 0x010001.
 * @property {Object} RS384 - Configuration for the RSA Signature Algorithm (RSASSA-PKCS1-v1_5) using SHA-384 hash, a modulus length of 3072 bits, and a public exponent of 0x010001.
 * @property {Object} RS512 - Configuration for the RSA Signature Algorithm (RSASSA-PKCS1-v1_5) using SHA-512 hash, a modulus length of 4096 bits, and a public exponent of 0x010001.
 */
export const ALGOS = {
	ES256: {
		name: 'ECDSA',
		namedCurve: 'P-256',
		hash: 'SHA-256',
	},
	ES384: {
		name: 'ECDSA',
		namedCurve: 'P-384',
		hash: 'SHA-384',
	},
	ES512: {
		name: 'ECDSA',
		namedCurve: 'P-521',
		hash: 'SHA-512',
	},
	RS256: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: 'SHA-256',
		modulusLength: 2048,
		publicExponent: new Uint8Array([1, 0, 1]),
	},
	RS384: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: 'SHA-384',
		modulusLength: 3072,
		publicExponent: new Uint8Array([1, 0, 1]),
	},
	RS512: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: 'SHA-512',
		modulusLength: 4096,
		publicExponent: new Uint8Array([1, 0, 1]),
	},
	// PS256: {
	// 	name: 'RSASSA-PSS',
	// 	hash: 'SHA-256',
	// 	saltLength: 32, // Optional, but recommended
	// 	maskLength: 32, // Optional, but recommended
	// },
	// HS256: {
	// 	name: 'HMAC',
	// 	hash: 'SHA-256',
	// },
};
