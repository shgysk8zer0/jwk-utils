import { ALGOS, EdDSA, SHA256 } from './consts.js';
/**
 * Calculates the key ID (kid) for a given JSON Web Key (JWK).
 *
 * @param {CryptoKey} key - The JWK to calculate the key ID for.
 * @returns {Promise<string | TypeError>} A promise that resolves to the calculated key ID or a TypeError is key cannot be extracted.
 * @throws {Error} - If there's an error exporting or hashing the JWK.
 */
export async function getKeyId(key) {
	if (! (key instanceof CryptoKey)) {
		throw new TypeError('Cannot get hash of a non-CryptoKey.');
	} else if (! key.extractable) {
		return new TypeError('Cannot extract/export key.');
	} else {
		const data = JSON.stringify(await crypto.subtle.exportKey('jwk', key));
		const digest = await crypto.subtle.digest(SHA256, new TextEncoder().encode(data));
		return new Uint8Array(digest).toHex();
	}
}

/**
 * Finds the corresponding algorithm configuration for a given JSON Web Key (JWK).
 *
 * This function attempts to match the algorithm name or curve of the provided JWK
 * with the predefined algorithms in the `ALGOS` constant. It returns an array
 * containing the algorithm name (string) and the corresponding algorithm configuration
 * object from `ALGOS`, or `[null, null]` if no match is found.
 *
 * @param {Object} key - The JWK object to search for the algorithm.
 * @returns {Array<string | null, Object | null>} An array containing the algorithm name and configuration, or `[null, null]` if no match is found.
 */
export function findKeyAlgo(key) {
	if (key instanceof CryptoKey) {
		switch (key.algorithm.name) {
			case 'ECDSA':
				return Object.entries(ALGOS).find(([, { name, namedCurve }]) => (
					name === key.algorithm.name && namedCurve === key.algorithm.namedCurve
				)) ?? [null, null];

			case 'RSASSA-PKCS1-v1_5':
			case 'HMAC':
			case 'RSA-PSS':
				return Object.entries(ALGOS).find(([, { name, hash }]) => (
					name === key.algorithm.name && hash === key.algorithm.hash.name
				)) ?? [null, null];

			case 'Ed25519':
				return [EdDSA, ALGOS[EdDSA]];

			default:
				return [null, null];
		}
	} else if (typeof key?.crv === 'string') {
		return Object.entries(ALGOS).find(([, algo]) => algo.namedCurve === key.crv) ?? [null, null];
	} else if (typeof key?.alg === 'string' && key.alg in ALGOS) {
		return [key.al, ALGOS[key.alg]];
	} else {
		return [null, null];
	}
}
