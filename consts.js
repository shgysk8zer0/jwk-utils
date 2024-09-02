export const AUTH = 'Authorization';
export const ALPHABET = 'base64url';
export const MIME_TYPE = 'application/jwk+json';

export const ES256 = 'ES256';
export const ES384 = 'ES384';
export const ES512 = 'ES512';
export const RS256 = 'RS256';
export const RS384 = 'RS384';
export const RS512 = 'RS512';
export const HS256 = 'HS256';
export const HS384 = 'HS384';
export const HS512 = 'HS512';
export const PS256 = 'PS256';
export const PS384 = 'PS384';
export const PS512 = 'PS512';
export const EdDSA = 'EdDSA';
export const DEFAULT_ALGO = ES256;

export const SHA256 = 'SHA-256';
export const SHA384 = 'SHA-384';
export const SHA512 = 'SHA-512';

export const PUBLIC_EXPONENT = new Uint8Array([1, 0, 1]);

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
 * @property {Object} HS256 - Configuration for the HMAC algorithm using SHA-256 hash.
 * @property {Object} HS384 - Configuration for the HMAC algorithm using SHA-384 hash.
 * @property {Object} HS512 - Configuration for the HMAC algorithm using SHA-512 hash.
 * @property {Object} PS256 - Configuration for the RSA Signature Algorithm (RSA-PSS) using SHA-256 hash, a salt length of 32 bytes, a modulus length of 2048 bits, and a public exponent of 0x010001.
 * @property {Object} PS384 - Configuration for the RSA Signature Algorithm (RSA-PSS) using SHA-384 hash, a salt length of 32 bytes, a modulus length of 3072 bits, and a public exponent of 0x010001.
 * @property {Object} PS512 - Configuration for the RSA Signature Algorithm (RSA-PSS) using SHA-512 hash, a salt length of 32 bytes, a modulus length of 4096 bits, and a public exponent of 0x010001.
 * @property {Object} EdDSA - Configuration for the Edwards-Curve Digital Signature Algorithm (EdDSA) using the Ed25519 curve. Limited support.
 */
export const ALGOS = {
	ES256: {
		name: 'ECDSA',
		namedCurve: 'P-256',
		hash: SHA256,
	},
	ES384: {
		name: 'ECDSA',
		namedCurve: 'P-384',
		hash: SHA384,
	},
	ES512: {
		name: 'ECDSA',
		namedCurve: 'P-521',
		hash: SHA512,
	},
	RS256: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: SHA256,
		modulusLength: 2048,
		publicExponent: PUBLIC_EXPONENT,
	},
	RS384: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: SHA384,
		modulusLength: 3072,
		publicExponent: PUBLIC_EXPONENT,
	},
	RS512: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: SHA512,
		modulusLength: 4096,
		publicExponent: PUBLIC_EXPONENT,
	},
	HS256: {
		name: 'HMAC',
		hash: SHA256,
	},
	HS384: {
		name: 'HMAC',
		hash: SHA384,
	},
	HS512: {
		name: 'HMAC',
		hash: SHA512,
	},
	PS256: {
		name: 'RSA-PSS',
		hash: SHA256,
		saltLength: 32,
		modulusLength: 2048,
		publicExponent: PUBLIC_EXPONENT,
	},
	PS384: {
		name: 'RSA-PSS',
		hash: SHA384,
		saltLength: 32,
		modulusLength: 3072,
		publicExponent: PUBLIC_EXPONENT,
	},
	PS512: {
		name: 'RSA-PSS',
		hash: SHA512,
		saltLength: 32,
		modulusLength: 4096,
		publicExponent: PUBLIC_EXPONENT,
	},
	EdDSA: {
		name: 'Ed25519',
		namedCurve: 'Ed25519',
	},
};
