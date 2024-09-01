import '@shgysk8zer0/polyfills';

import { MIME_TYPE, DEFAULT_ALGO, ALGOS } from './consts.js';
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
 * @returns {Promise<CryptoKeyPair | CryptoKey>} A promise that resolves to the generated JWK pair.
 * @throws {Error} - If there's an error generating the JWK pair.
 */
export async function generateJWK(algo = DEFAULT_ALGO) {
	return await crypto.subtle.generateKey(
		ALGOS[algo],
		true,
		['sign', 'verify']
	);
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
 * Loads a JSON Web Key (JWK) from a File object.
 *
 * @param {File} file - The File object containing the JWK data.
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported JWK.
 * @throws {TypeError} - If the provided object is not a File object or the file has an incorrect MIME type.
 * @throws {Error} - If there's an error parsing the JWK data or importing the key.
 */
export async function loadJWKFromFile(file) {
	if (! (file instanceof File)) {
		throw new TypeError('Cannot import key from a non-file.');
	} else if (file.type !== MIME_TYPE) {
		throw new TypeError(`${file.name} has a mime-type of ${file.type}, not ${MIME_TYPE}.`);
	} else {
		const key = JSON.parse(await file.text());
		return await importJWK(key);
	}
}

/**
 * Imports a JSON Web Key (JWK) into a CryptoKey object.
 *
 * @param {Object} key - The JWK data to import.
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported CryptoKey object.
 * @throws {Error} - If there's an error importing the JWK.
 */
export async function importJWK(key) {
	const algo = findKeyAlgo(key)[1];

	return await crypto.subtle.importKey(
		'jwk',
		key,
		algo,
		key.ext,
		key.key_ops
	);
}

/**
 * Imports a JSON Web Key (JWK) from a base64-encoded string.
 *
 * @param {string} keyData - The base64-encoded JWK data.
 * @returns {Promise<CryptoKey | null>} A promise that resolves to the imported JWK.
 * @throws {Error} - If there's an error decoding the base64 string, parsing the JWK data, or importing the key.
 */
export async function importJWKFromBase64(keyData) {
	if (typeof keyData === 'string' && keyData.length !== 0) {
		const key = JSON.parse(new TextDecoder().decode(Uint8Array.fromBase64(keyData)));

		return await importJWK(key);
	} else {
		return null;
	}
}

/**
 * Fetches a JSON Web Key (JWK) from a specified URL.
 *
 * @param {string | URL} url - The URL of the JWK resource.
 * @param {object} [options] - Optional options for the fetch request.
 * @param {Headers | object} [options.headers] - The headers to include in the fetch request. Defaults to a `Headers` object with `Accept: application/jwk+json`.
 * @param {string} [options.method='GET'] - The HTTP method to use for the fetch request. Defaults to 'GET'.
 * @param {string} [options.referrerPolicy='no-referrer'] - The referrer policy to use for the fetch request. Defaults to 'no-referrer'.
 * @param {string} [options.redirect='error'] - The redirect policy to use for the fetch request. Defaults to 'error'.
 * @param {string} [options.crossOrigin='anonymous'] - The cross-origin isolation mode to use for the fetch request. Defaults to 'anonymous'.
 * @param {string} [options.integrity] - The integrity check to perform on the response.
 * @param {AbortSignal} [options.signal] - An AbortSignal object to abort the fetch request.
 * @returns {Promise<CryptoKey|null>} A promise that resolves to the imported JWK if successful, or null if the fetch fails or the response is not a valid JWK.
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
			return null;
		}
	} catch {
		return null;
	}
}
