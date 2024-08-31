import { generateJWKPair, createOriginAuthToken, decodeOriginToken } from './jwk-utils.js';

const { publicKey, privateKey } = await generateJWKPair();

const token = await createOriginAuthToken('https://example.com', privateKey);
await decodeOriginToken(token, 'https://example.com', publicKey);
