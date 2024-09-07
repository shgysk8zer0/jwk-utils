import { importJWKFromBase64 } from './jwk.js';
/**
 * Imports a JSON Web Key (JWK) from an environment variable.
 *
 * @param {string} name - The name of the environment variable containing the base64-encoded JWK.
 * @returns {Promise<CryptoKey | null>} A promise that resolves to the imported JWK.
 * @throws {Error} - If the environment variable is not defined or the JWK cannot be imported.
 */
export const importJWKFromEnv = async name => await importJWKFromBase64(globalThis?.process?.env[name.toUpperCase()]);

/**
 * Retrieves the public JWK from the environment variable 'PUBLIC_JWK'.
 *
 * @returns {Promise<CryptoKey | null>} A promise that resolves to the imported public JWK.
 * @throws {Error} - If the environment variable is not defined or the JWK cannot be imported.
 */
export const getPublicKey = async () => await importJWKFromEnv('PUBLIC_JWK');

/**
 * Retrieves the private JWK from the environment variable 'PRIVATE_JWK'.
 *
 * @returns {Promise<CryptoKey | null>} A promise that resolves to the imported private JWK.
 * @throws {Error} - If the environment variable is not defined or the JWK cannot be imported.
 */
export const getPrivateKey = async () => await importJWKFromEnv('PRIVATE_JWK');
