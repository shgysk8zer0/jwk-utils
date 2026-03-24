import { DEFAULT_ALGO, ALGOS } from './consts.js';

const NL = '\n';
const PEM_PRIVATE_HEADER = '-----BEGIN PRIVATE KEY-----';
const PEM_PRIVATE_FOOTER = '-----END PRIVATE KEY-----';
const PEM_PUBLIC_HEADER = '-----BEGIN PUBLIC KEY-----';
const PEM_PUBLIC_FOOTER = '-----END PUBLIC KEY-----';
const PUBLIC_KEY_USAGES = ['verify', 'encrypt', 'wrapKey'];
const PRIVATE_KEY_USAGES = ['sign', 'decrypt', 'unwrapKey', 'deriveKey', 'deriveBits'];

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
 * @returns {Promise<Readonly<{publicKey: CryptoKey|null, privateKey: CryptoKey|null}>>}
 */
export async function importFromPEM(pem, algorithm = DEFAULT_ALGO, extractable = true, keyUsages = ['sign', 'verify']) {
	let publicKey = null, privateKey = null;

	if (pem.includes(PEM_PRIVATE_HEADER) && pem.includes(PEM_PRIVATE_FOOTER)) {
		const start = pem.indexOf(PEM_PRIVATE_HEADER);
		const end = pem.indexOf(PEM_PRIVATE_FOOTER, start);

		privateKey = await crypto.subtle.importKey(
			'pkcs8',
			Uint8Array.fromBase64(
				pem.trim().substring(start + PEM_PRIVATE_HEADER.length, end).replace(/\s+/g, '')
			).buffer,
			ALGOS[algorithm],
			extractable,
			keyUsages.filter(u => PRIVATE_KEY_USAGES.includes(u))
		);
	}

	if (pem.includes(PEM_PUBLIC_HEADER) && pem.includes(PEM_PUBLIC_FOOTER)) {
		const start = pem.indexOf(PEM_PUBLIC_HEADER);
		const end = pem.indexOf(PEM_PUBLIC_FOOTER, start);
		publicKey = await crypto.subtle.importKey(
			'spki',
			Uint8Array.fromBase64(
				pem.trim().substring(start + PEM_PUBLIC_HEADER.length, end).replace(/\s+/g, '')
			).buffer,
			ALGOS[algorithm],
			extractable,
			keyUsages.filter(u => PUBLIC_KEY_USAGES.includes(u))
		);
	}

	return Object.create(null, {
		publicKey: {
			value: publicKey,
			enumerable: true,
			writable: false,
			configurable: false,
		},
		privateKey: {
			value: privateKey,
			enumerable: true,
			writable: false,
			configurable: false,
		},
	});
}

/**
 * Converts a `CryptoKey` or pair into a PEM string
 *
 * @param {CryptoKey|CryptoKeyPair} key
 * @returns {Promise<string>}
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
