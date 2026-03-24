import {
	DEFAULT_ALGO, ALGOS, ES256, RS256, ES384, ES512, RS384, RS512, EdDSA, PS256, PS384, PS512,
	PEM_PRIVATE_HEADER, PEM_PRIVATE_FOOTER, PEM_PUBLIC_HEADER, PEM_PUBLIC_FOOTER,
	PUBLIC_KEY_USAGES, PRIVATE_KEY_USAGES,
} from './consts.js';

const NL = '\n';
const WS = /\s+/g;

function split(str, len = 64) {
	let result = '';
	for (let i = 0; i < str.length; i += len) {
		result += str.slice(i, i + len) + NL;
	}
	return result.trim();
}

/**
 * Parses a PEM string and returns an object with any public/private key
 *
 * @param {string} pem
 * @param {string} [algorithm="ES256"]
 * @param {boolean} [extractable=true]
 * @param {KeyUsage[]} [keyUsages=["sign", "verify"]]
 * @returns {Promise<CryptoKey>}
 */
export async function importFromPEM(pem, algorithm = DEFAULT_ALGO, extractable = true, keyUsages = ['sign', 'verify']) {
	if (pem.includes(PEM_PRIVATE_HEADER) && pem.includes(PEM_PRIVATE_FOOTER)) {
		const start = pem.indexOf(PEM_PRIVATE_HEADER);
		const end = pem.indexOf(PEM_PRIVATE_FOOTER, start);

		return await crypto.subtle.importKey(
			'pkcs8',
			Uint8Array.fromBase64(
				pem.trim().substring(start + PEM_PRIVATE_HEADER.length, end).replace(WS, '')
			).buffer,
			ALGOS[algorithm],
			extractable,
			keyUsages.filter(u => PRIVATE_KEY_USAGES.includes(u))
		);
	} else if (pem.includes(PEM_PUBLIC_HEADER) && pem.includes(PEM_PUBLIC_FOOTER)) {
		const start = pem.indexOf(PEM_PUBLIC_HEADER);
		const end = pem.indexOf(PEM_PUBLIC_FOOTER, start);

		return await crypto.subtle.importKey(
			'spki',
			Uint8Array.fromBase64(
				pem.trim().substring(start + PEM_PUBLIC_HEADER.length, end).replace(WS, '')
			).buffer,
			ALGOS[algorithm],
			extractable,
			keyUsages.filter(u => PUBLIC_KEY_USAGES.includes(u))
		);
	}
}

/**
 * Converts a `CryptoKey` or pair into a PEM string
 *
 * @param {CryptoKey|CryptoKeyPair} key
 * @returns {Promise<string|string[]>} The PEM string for a single key or an array for a key pair
 */
export async function exportPEM(key) {
	if (key instanceof CryptoKey && key.extractable) {
		switch(key.type) {
			case 'private':
				return `${PEM_PRIVATE_HEADER}${NL}${(await crypto.subtle.exportKey('pkcs8', key).then(buff => split(new Uint8Array(buff).toBase64())))}${NL}${PEM_PRIVATE_FOOTER}`;

			case 'public':
				return `${PEM_PUBLIC_HEADER}${NL}${await crypto.subtle.exportKey('spki', key).then(buff => split(new Uint8Array(buff).toBase64()))}${NL}${PEM_PUBLIC_FOOTER}`;

			default:
				throw new TypeError(`Unsupported key type: "${key.type}.`);
		}
	} else if (key?.publicKey instanceof CryptoKey && key?.privateKey instanceof CryptoKey) {
		return await Promise.all([exportPEM(key.publicKey), exportPEM(key.privateKey)]);
	} else if (key?.publicKey instanceof CryptoKey) {
		return exportPEM(key.publicKey);
	} else if (key?.privateKey instanceof CryptoKey) {
		return exportPEM(key.privateKey);
	}
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemES256(strings) {
	return await importFromPEM(String.raw(strings).trim(), ES256);
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemES384(strings) {
	return await importFromPEM(String.raw(strings).trim(), ES384);
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemES512(strings) {
	return await importFromPEM(String.raw(strings).trim(), ES512);
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemRS256(strings) {
	return await importFromPEM(String.raw(strings).trim(), RS256);
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemRS384(strings) {
	return await importFromPEM(String.raw(strings).trim(), RS384);
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemRS512(strings) {
	return await importFromPEM(String.raw(strings).trim(), RS512);
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemPS256(strings) {
	return await importFromPEM(String.raw(strings).trim(), PS256);
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemPS384(strings) {
	return await importFromPEM(String.raw(strings).trim(), PS384);
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemPS512(strings) {
	return await importFromPEM(String.raw(strings).trim(), PS512);
}

/**
 *
 * @param {TemplateStringsArray} strings
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function pemEdDSA(strings) {
	return await importFromPEM(String.raw(strings).trim(), EdDSA);
}
