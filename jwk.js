import '@shgysk8zer0/polyfills';

import { MIME_TYPE, DEFAULT_ALGO, ALGOS, HS256 } from './consts.js';
import { findKeyAlgo } from './utils.js';

/**
 * Generates a new JSON Web Key (JWK) pair with the specified algorithm.
 *
 * @deprecated
 * @param {string} algo - The algorithm to use for the JWK pair. Defaults to `"ES256"`.
 * @returns {Promise<CryptoKeyPair>} A promise that resolves to the generated JWK pair.
 * @throws {Error} - If there's an error generating the JWK pair.
 */
export async function generateJWKPair(algo = DEFAULT_ALGO) {
	console.warn('`generateJWKPair` is deprecated. Please use `generateJWK` instead.');
	return await generateJWK(algo);
}

/**
 * Generates a new JSON Web Key (JWK) pair or secret key (single) with the specified algorithm.
 *
 * @param {string} algo - The algorithm to use for the JWK pair. Defaults to `"ES256"`.
 * @param {object} [options] - Optional options for the token creation.
 * @param {boolean} [extractabl=truee] - Whether or not the key may be extracted/exported.
 * @returns {Promise<CryptoKeyPair | CryptoKey>} A promise that resolves to the generated JWK pair.
 * @throws {Error} - If there's an error generating the JWK pair.
 */
export async function generateJWK(algo = DEFAULT_ALGO, { extractable = true } = {}) {
	return await crypto.subtle.generateKey(
		ALGOS[algo],
		extractable,
		['sign', 'verify']
	);
}

/**
 * Imports a JSON Web Key (JWK) into a CryptoKey object.
 *
 * @param {object | string} key - The JWK data to import or its JSON.
 * @returns {Promise<CryptoKey | Error>} A promise that resolves to the imported CryptoKey object or any Error.
 */
export async function importJWK(key) {
	try {
		if (typeof key === 'string') {
			return await importJWK(JSON.parse(key));
		} else {
			const algo = findKeyAlgo(key)[1];

			if (typeof algo?.name === 'string') {
				return await crypto.subtle.importKey(
					'jwk',
					key,
					algo,
					key.ext,
					key.key_ops
				);
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
 * @param {Uint8Array | string} raw - The raw data or string to import.
 * @param {string} algorithm - The desired algorithm for the imported key.
 * @param {boolean} [extractable=true] - Whether the imported key can be extracted.
 * @param {KeyUsage[]} [usages=['sign', 'verify']] - The allowed usages for the imported key.
 * @returns {Promise<CryptoKey | Error>} A promise that resolves to the imported CryptoKey object or any error that occurs.
 */
export async function importRawKey(raw, { algorithm = HS256, extractable = true, usages = ['sign', 'verify'] } = {}) {
	try {
		if (typeof raw === 'string') {
			return await importRawKey(new TextEncoder().encode(raw), { algorithm, extractable, usages });
		} else {
			return await crypto.subtle.importKey('raw', raw, ALGOS[algorithm], extractable, usages);
		}
	} catch(err) {
		return new Error('Error importing key from raw data', { cause: err });
	}
}

/**
 *
 * @param {CryptoKey} key - The key to export.
 * @returns {object | Error} The exported key or any error in exporing it.
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
 * @throws {Error} - If there's an error exporting or encoding the JWK.
 */
export async function base64EncodeJWK(key) {
	const extracted = await crypto.subtle.exportKey('jwk', key);
	return new TextEncoder().encode(JSON.stringify(extracted)).toBase64();
}

/**
 * Creates a new File object containing a JSON Web Key (JWK) in a specified format.
 *
 * @param {CryptoKey} key - The JWK to export.
 * @param {string} [name] - The desired name for the file. If not provided, a default name based on the key type is used.
 * @returns {Promise<File>} A promise that resolves to the created File object.
 * @throws {Error} - If there's an error exporting the JWK or creating the file.
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
 * @param {CryptoKey} key - The JWK to export.
 * @returns {Promise<Blob>} A promise that resolves to the created Blob object.
 * @throws {Error} - If there's an error exporting the JWK or creating the file.
 */
export async function createJWKBlob(key) {
	const extracted = await crypto.subtle.exportKey('jwk', key);
	return new Blob([JSON.stringify(extracted)], { type: MIME_TYPE });
}

/**
 * Loads a JSON Web Key (JWK) from a Blob object.
 *
 * @param {Blob | File} blob - The Blob (including File) object containing the JWK data.
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported JWK.
 * @throws {TypeError} - If the provided object is not a Blob object or the file has an incorrect MIME type.
 * @throws {Error} - If there's an error parsing the JWK data or importing the key.
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
 * @returns {Promise<CryptoKey | Error>} A promise that resolves to the imported JWK or any Error.
 */
export async function importJWKFromBase64(keyData) {
	if (typeof keyData === 'string' && keyData.length !== 0) {
		const key = JSON.parse(new TextDecoder().decode(Uint8Array.fromBase64(keyData)));

		return await importJWK(key);
	} else {
		return new TypeError('Key data to decode must me a non-empty string.');
	}
}

/**
 * Fetches a JSON Web Key (JWK) from a specified URL.
 *
 * @param {string | URL} url - The URL of the JWK resource.
 * @param {FetchInit | object} [options] - Optional options for the fetch request.
 * @param {Headers | object} [options.headers] - The headers to include in the fetch request. Defaults to a `Headers` object with `Accept: application/jwk+json`.
 * @param {string} [options.method='GET'] - The HTTP method to use for the fetch request. Defaults to 'GET'.
 * @param {string} [options.referrerPolicy='no-referrer'] - The referrer policy to use for the fetch request. Defaults to 'no-referrer'.
 * @param {string} [options.redirect='error'] - The redirect policy to use for the fetch request. Defaults to 'error'.
 * @param {string} [options.crossOrigin='anonymous'] - The cross-origin isolation mode to use for the fetch request. Defaults to 'anonymous'.
 * @param {string} [options.integrity] - The integrity check to perform on the response.
 * @param {AbortSignal} [options.signal] - An AbortSignal object to abort the fetch request.
 * @returns {Promise<CryptoKey | Error>} A promise that resolves to the imported JWK if successful, or Error if the fetch fails or the response is not a valid JWK.
 */
export async function fetchJWK(url, {
	headers = new Headers({ Accept: MIME_TYPE }),
	method = 'GET',
	referrerPolicy = 'no-referrer',
	redirect = 'error',
	crossOrigin = 'anonymous',
	integrity,
	signal,
} = {}) {
	if (! (headers instanceof Headers)) {
		headers = new Headers(headers);
	}

	if (! headers.has('Accept')) {
		headers.set('Accept', MIME_TYPE);
	}

	try {
		const resp = await fetch(url, { headers, method, referrerPolicy, redirect, crossOrigin, integrity, signal });

		if (resp.ok && resp.headers.get('Content-Type').split(';')[0] === MIME_TYPE) {
			return await importJWK(await resp.json());
		} else {
			return new Error(`${url} [${resp.status} ${resp.statusText}]`);
		}
	} catch(err) {
		return err;
	}
}
