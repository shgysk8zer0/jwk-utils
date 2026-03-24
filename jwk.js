import { MIME_TYPE, DEFAULT_ALGO, ALGOS, HS256, FETCH_INIT, SUPPORTED_ALGOS, SIGN_USAGE } from './consts.js';
import { findKeyAlgo } from './utils.js';

/**
 * @typedef {"RSA" | "EC" | "oct" | "OKP"} RFC7517KTY
 */

/**
 * @typedef {
 *   | "sign" | "verify"
 *   | "encrypt" | "decrypt"
 *   | "wrapKey" | "unwrapKey"
 *   | "deriveKey" | "deriveBits"
 * } RFC7517KeyOp
 */

/**
 * @typedef {"sig" | "enc"} RFC7517Use
 */

/**
 * Base (common) JWK fields
 * @typedef {object} RFC7517JWKBase
 * @property {RFC7517KTY} kty
 * @property {RFC7517Use} [use]
 * @property {RFC7517KeyOp[]} [key_ops]
 * @property {string} [alg]
 * @property {string} [kid]
 * @property {string} [x5u]
 * @property {string[]} [x5c]
 * @property {string} [x5t]
 * @property {string} ["x5t#S256"]
 */

/**
 * RSA JWK
 * @typedef {RFC7517JWKBase & {
 *   kty: "RSA",
 *   n: string,
 *   e: string,
 *   d?: string,
 *   p?: string,
 *   q?: string,
 *   dp?: string,
 *   dq?: string,
 *   qi?: string,
 *   oth?: {
 *     r: string,
 *     d: string,
 *     t: string
 *   }[]
 * }} RFC7517RSAJWK
 */

/**
 * EC JWK (Weierstrass curves)
 * @typedef {"P-256" | "P-384" | "P-521" | "secp256k1"} RFC7518Curve
 *
 * @typedef {RFC7517JWKBase & {
 *   kty: "EC",
 *   crv: RFC7518Curve,
 *   x: string,
 *   y: string,
 *   d?: string
 * }} RFC7517ECJWK
 */

/**
 * Symmetric (octet sequence) JWK
 * @typedef {RFC7517JWKBase & {
 *   kty: "oct",
 *   k: string
 * }} RFC7517OctJWK
 */

/**
 * OKP JWK (RFC 8037)
 * @typedef {"Ed25519" | "Ed448" | "X25519" | "X448"} RFC8037Curve
 *
 * @typedef {RFC7517JWKBase & {
 *   kty: "OKP",
 *   crv: RFC8037Curve,
 *   x: string,
 *   d?: string
 * }} RFC7517OKPJWK
 */

/**
 * Full JWK union (RFC 7517 + RFC 8037)
 * @typedef { RFC7517RSAJWK | RFC7517ECJWK | RFC7517OctJWK | RFC7517OKPJWK } RFC7517JWK
 */

/**
 * Generates a new JSON Web Key (JWK) pair with the specified algorithm.
 *
 * @deprecated
 * @param {string} [algo='ES256'] - The algorithm to use for the JWK pair. Defaults to `"ES256"`.
 * @returns {Promise<CryptoKeyPair>} A promise that resolves to the generated JWK pair.
 * @throws {Error} If there's an error generating the JWK pair.
 */
export async function generateJWKPair(algo = DEFAULT_ALGO) {
	console.warn('`generateJWKPair` is deprecated. Please use `generateJWK` instead.');
	return await generateJWK(algo);
}

/**
 * Generates a new JSON Web Key (JWK) pair or secret key (single) with the specified algorithm.
 *
 * @param {string} [algo='ES256'] - The algorithm to use for the JWK pair. Defaults to `"ES256"`.
 * @param {object} [options] - Optional options for the token creation.
 * @param {boolean} [extractable=true] - Whether or not the key may be extracted/exported.
 * @param {KeyUsage[]} [usages=['sign', 'verify']] - The allowed usages for the key.
 * @returns {Promise<CryptoKeyPair|CryptoKey>} A promise that resolves to the generated JWK pair.
 * @throws {Error} If there's an error generating the JWK pair.
 */
export async function generateJWK(algo = DEFAULT_ALGO, { extractable = true, usages = SIGN_USAGE } = {}) {
	return await crypto.subtle.generateKey(ALGOS[algo], extractable, usages);
}

/**
 *
 * @param {CryptoKey|CryptoKeyPair} key
 * @returns {Promise<string>}
 */
export async function getKid(key) {
	if (key?.publicKey instanceof CryptoKey) {
		return await generateJWK(key.publicKey);
	} else if (! (key instanceof CryptoKey)) {
		throw new TypeError('Key must be a `CryptoKey`');
	} else if (! key.extractable) {
		throw new TypeError('Key must be extractable.');
	} else {
		const jwk = await crypto.subtle.exportKey('jwk', key);
		const keyMembers = {
			EC:  ['crv', 'kty', 'x', 'y'],
			RSA: ['e', 'kty', 'n'],
			OKP: ['crv', 'kty', 'x'],
			oct: ['k', 'kty'],
		};

		if (! (jwk.kty in keyMembers)) {
			throw new Error(`Unsupported key type: ${jwk.kty}`);
		} else {
			const fields = keyMembers[jwk.kty];

			// Build in sorted order explicitly — do NOT sort after the fact
			const payload = JSON.stringify(Object.fromEntries(fields.map(k => [k, jwk[k]])));

			const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));

			return new Uint8Array(digest).toBase64({ alphabet: 'base64url', omitPadding: true });
		}
	}
}

/**
 * Fetch an array of keys from a `.well-known/jwks.json`
 *
 * @param {string} origin The origin to fetch the JWKS from (e.g., 'https://example.com').
 * @param {RequestInit} [fetchInit] Optional fetch initialization options.
 * @returns {Promise<RFC7517JWK[]>} An array of key objects, or an empty array if an error occurs or no keys are found.
 */
export async function fetchWellKnownKeys(origin, fetchInit = FETCH_INIT) {
	const url = new URL('/.well-known/jwks.json', origin);
	const resp = await fetch(url, fetchInit);

	if (resp.ok) {
		return await resp.json()
			.then(data => Array.isArray(data?.keys) ? data.keys : [])
			.catch(() => []);
	} else {
		return [];
	}
}

/**
 * Fetch and import a public key from a `.well-known/jwks.json` URL
 *
 * @param {string} origin The origin to fetch the JWKS from (e.g., 'https://example.com').
 * @param {RequestInit} [fetchInit=FETCH_INIT] Optional fetch initialization options.
 * @param {boolean} [extractable=false] Whether the imported key should be extractable.
 * @returns {Promise<CryptoKey|null>} A  CryptoKey object if a suitable key is found and imported, or null otherwise.
 */
export async function fetchWellKnownKey(origin, fetchInit = FETCH_INIT, extractable = false) {
	const keys = await fetchWellKnownKeys(origin, fetchInit);

	if (keys.length !== 0) {
		const key = keys.find(key => key.use === 'sig' && SUPPORTED_ALGOS.includes(key.alg));

		return await importRFC7517JWK(key, extractable);
	} else {
		return null;
	}
}

/**
 * Imports a JSON Web Key (JWK) in the RFC7517 format.
 *
 * @param {RFC7517JWK} keyObj
 * @param {boolean} [extractable=false] Whether the key can be extracted.
 * @returns {Promise<CryptoKey|null>} The imported CryptoKey or null if there were any errors.
 */
export async function importRFC7517JWK(keyObj, extractable = false) {
	if (typeof keyObj?.alg === 'string') {
		return await crypto.subtle.importKey(
			'jwk',
			keyObj,
			ALGOS[keyObj.alg],
			extractable,
			Array.isArray(keyObj.key_ops) ? keyObj.key_ops : keyObj.use === 'sig' ? ['verify'] : ['encrypt'],
		).catch(() => null);
	} else {
		return null;
	}
}

/**
 * Exports a CryptoKey or CryptoKeyPair as a JSON Web Key (JWK) in the RFC7517 format.
 *
 * @param {CryptoKey|CryptoKeyPair} key
 * @param {object} [options] Export options.
 * @param {string} [options.kid] Optional ID for the key, which will be generated if omitted.
 * @returns {Promise<RFC7517JWK|null>} The exported JWK or null if there were any errors.
 */
export async function exportAsRFC7517JWK(key, { kid } = {}) {
	if (key?.publicKey instanceof CryptoKey) {
		return await exportAsRFC7517JWK(key.publicKey, { kid: typeof kid === 'string' ? kid : await getKid(key.publicKey) });
	} else if (key instanceof CryptoKey && key.extractable) {
		const data = await crypto.subtle.exportKey('jwk', key);
		const { kty, key_ops, ...rest } = data;
		// Remove unnecessary stuff
		delete rest.ext;

		// This should convert a JWK to RFC7517 format, which is different from the JWK format
		return {
			kty,
			alg: findKeyAlgo(data)[0],
			kid: typeof kid === 'string' ? kid : await getKid(key),
			use: key_ops?.includes('verify') || key_ops?.includes('sign') ? 'sig' : 'enc',
			key_ops,
			...rest
		};
	} else {
		return null;
	}
}

/**
 *
 * @param  {...CryptoKey} keys
 * @returns {Promise<{keys: JsonWebKeyRFC7517[]}>}
 */
export async function exportAsRFC7517JWKSet(...keys) {
	return { keys: await Promise.all(keys.map(key => exportAsRFC7517JWK(key))) };
}

/**
 * Imports a JSON Web Key (JWK) into a CryptoKey object.
 *
 * @param {object|string} key - The JWK data to import or its JSON.
 * @returns {Promise<CryptoKey|Error>} A promise that resolves to the imported CryptoKey object or any Error.
 */
export async function importJWK(key) {
	try {
		if (typeof key === 'string') {
			return await importJWK(JSON.parse(key));
		} else {
			const algo = findKeyAlgo(key)[1];

			if (typeof algo?.name === 'string') {
				return await crypto.subtle.importKey('jwk', key, algo, key.ext, key.key_ops);
			} else {
				return new TypeError('Invalid or unsupported algorithm.');
			}
		}
	} catch(err) {
		return new Error('Error importing key from JWK.', { cause: err });
	}
}

/**
 * Imports raw data or a string into a CryptoKey object.
 *
 * @param {Uint8Array|string} raw - The raw data or string to import.
 * @param {string} [algorithm='HS256'] - The desired algorithm for the imported key.
 * @param {boolean} [extractable=true] - Whether the imported key can be extracted.
 * @param {KeyUsage[]} [usages=['sign', 'verify']] - The allowed usages for the imported key.
 * @returns {Promise<CryptoKey|Error>} A promise that resolves to the imported CryptoKey object or any error that occurs.
 */
export async function importRawKey(raw, { algorithm = HS256, extractable = true, usages = ['sign', 'verify'] } = {}) {
	try {
		if (typeof raw === 'string') {
			return await importRawKey(new TextEncoder().encode(raw), { algorithm, extractable, usages });
		} else {
			return await crypto.subtle.importKey('raw', raw, ALGOS[algorithm], extractable, usages);
		}
	} catch(err) {
		return new Error('Error importing key from raw data.', { cause: err });
	}
}

/**
 *
 * @param {CryptoKey} key - The key to export.
 * @returns {Promise<object|Error>} The exported key or any error in exporing it.
 */
export async function exportJWK(key) {
	if (! (key instanceof CryptoKey)) {
		return new TypeError('Exporting of keys requires a `CryptoKey`.');
	} else {
		return await crypto.subtle.exportKey('jwk', key).catch(err => err);
	}
}

/**
 * Encodes a JSON Web Key (JWK) as a base64 string.
 *
 * @param {CryptoKey} key - The JWK to encode.
 * @returns {Promise<string>} A promise that resolves to the base64-encoded JWK.
 * @throws {Error} If there's an error exporting or encoding the JWK.
 */
export async function base64EncodeJWK(key) {
	const extracted = await crypto.subtle.exportKey('jwk', key);
	return new TextEncoder().encode(JSON.stringify(extracted)).toBase64();
}

/**
 * Creates a new File object containing a JSON Web Key (JWK) in a specified format.
 *
 * @param {CryptoKey} key - The `CryptoKey` to export to `File`.
 * @param {string} [name] - The desired name for the file. If not provided, a default name based on the key type is used.
 * @returns {Promise<File>} A promise that resolves to the created File object.
 * @throws {Error} If there's an error exporting the JWK or creating the file.
 */
export async function createJWKFile(key, name) {
	const extracted = await crypto.subtle.exportKey('jwk', key);

	if (typeof name === 'string' && name.length !== 0) {
		return new File([JSON.stringify(extracted)], name, { type: MIME_TYPE });
	} else {
		return new File([JSON.stringify(extracted)], `${key.algorithm.name}-${key.type}.jwk`, { type: MIME_TYPE});
	}
}

/**
 * Creates a new File object containing a JSON Web Key (JWK) in a specified format.
 *
 * @param {CryptoKey} key - The `CryptoKey` to export to `Blob`.
 * @returns {Promise<Blob>} A promise that resolves to the created Blob object.
 * @throws {Error} If there's an error exporting the JWK or creating the file.
 */
export async function createJWKBlob(key) {
	const extracted = await crypto.subtle.exportKey('jwk', key);
	return new Blob([JSON.stringify(extracted)], { type: MIME_TYPE });
}

/**
 * Loads a JSON Web Key (JWK) from a Blob object.
 *
 * @param {Blob|File} blob - The Blob (including File) object containing the JWK data.
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported JWK.
 * @throws {TypeError} If the provided object is not a Blob object or the file has an incorrect MIME type.
 * @throws {Error} If there's an error parsing the JWK data or importing the key.
 */
export async function loadJWKFromBlob(blob) {
	if (! (blob instanceof Blob)) {
		throw new TypeError('Cannot import key from a non-file or blob.');
	} else if (blob.type !== MIME_TYPE) {
		throw new TypeError(`${blob?.name ?? 'Blob'} has a mime-type of "${blob.type}", not ${MIME_TYPE}.`);
	} else {
		const key = JSON.parse(await blob.text());
		return await importJWK(key);
	}
}

/**
 * Imports a JSON Web Key (JWK) from a base64-encoded string.
 *
 * @param {string} keyData - The base64-encoded JWK data.
 * @returns {Promise<CryptoKey|Error>} A promise that resolves to the imported JWK or any Error.
 */
export async function importJWKFromBase64(keyData) {
	try {
		if (typeof keyData === 'string' && keyData.length !== 0) {
			const key = JSON.parse(new TextDecoder().decode(Uint8Array.fromBase64(keyData)));

			return await importJWK(key);
		} else {
			return new TypeError('Key data to decode must me a non-empty string.');
		}
	} catch(err) {
		return err;
	}
}

/**
 * Fetches a JSON Web Key (JWK) from a specified URL.
 *
 * @param {string|URL} url - The URL of the JWK resource.
 * @param {RequestInit} [options] - Optional options for the fetch request.
 * @param {Headers|object} [options.headers] - The headers to include in the fetch request. Defaults to a `Headers` object with `Accept: application/jwk+json`.
 * @param {string} [options.method='GET'] - The HTTP method to use for the fetch request. Defaults to 'GET'.
 * @param {string} [options.referrerPolicy='no-referrer'] - The referrer policy to use for the fetch request. Defaults to 'no-referrer'.
 * @param {string} [options.redirect='error'] - The redirect policy to use for the fetch request. Defaults to 'error'.
 * @param {string} [options.crossOrigin='anonymous'] - The cross-origin isolation mode to use for the fetch request. Defaults to 'anonymous'.
 * @param {string} [options.integrity] - The integrity check to perform on the response.
 * @param {AbortSignal} [options.signal] - An AbortSignal object to abort the fetch request.
 * @returns {Promise<CryptoKey|Error>} A promise that resolves to the imported JWK if successful, or Error if the fetch fails or the response is not a valid JWK.
 */
export async function fetchJWK(url, {
	headers = new Headers({ Accept: MIME_TYPE }),
	referrerPolicy = 'no-referrer',
	redirect = 'error',
	crossOrigin = 'anonymous',
	...fetchInit
} = {}) {
	if (! (headers instanceof Headers)) {
		headers = new Headers(headers);
	}

	if (! headers.has('Accept')) {
		headers.set('Accept', MIME_TYPE);
	}

	try {
		const resp = await fetch(url, { headers, referrerPolicy, redirect, crossOrigin, ...fetchInit });

		if (resp.ok && resp.headers.get('Content-Type').split(';')[0] === MIME_TYPE) {
			return await importJWK(await resp.json());
		} else {
			return new Error(`${url} [${resp.status} ${resp.statusText}]`);
		}
	} catch(err) {
		return err;
	}
}
