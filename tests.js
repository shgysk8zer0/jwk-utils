import { generateJWKPair, createOriginAuthToken, decodeOriginToken } from './jwk-utils.js';

const { publicKey, privateKey } = await generateJWKPair();

const token = await createOriginAuthToken('https://example.com', privateKey);

if (await decodeOriginToken(token, 'https://example.com', publicKey) === null) {
	throw new Error('Error decoding token.');
} else if (await decodeOriginToken('njkdfnfgkjfd', publicKey) !== null) {
	throw new Error('Decoding invalid tokens should return `null`.');
}
