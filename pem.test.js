import { describe, test } from 'node:test';
import assert from 'node:assert';
import { pemRS256 } from './pem.js';
import { ALGOS } from './consts.js';

describe('Test PEM tagged templates', async () => {
	const publicKey = await pemRS256`
	-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArySOtpwUUiXOFI19Bhgo
	fkRV/WnZST6G73FWXu3pDpOL8uxhVcAPRKZoauWO0uvin6UVYSHWGFwSKOq+3/Ip
	Ps010OMIJ0H8h6qM9iOTTdAmQNxIEVWj/9jkxe4idvW4JKDnZ6sXwbOQzNn+0c9P
	vf1cmd063qHKVyfXuK38rstbLEBa5kK0S1B/qwhiL+jiN/jMoN8K8G0rQxDv2/+Q
	qG4Xp+IvQdoFD8q+19c9fjInnfB/Sx8PiYErdiLIkci0Xlqrpm0m/dbKjM39hnVl
	sQMVcfqH0+5NYOGdZGlcUlARP3HM2k3d04MiELreTzeHGhIyn8QsjS0XVeaKihdH
	7QIDAQAB
	-----END PUBLIC KEY-----`;

	const privateKey = await pemRS256(`
	-----BEGIN PRIVATE KEY-----
	MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvJI62nBRSJc4U
	jX0GGCh+RFX9adlJPobvcVZe7ekOk4vy7GFVwA9Epmhq5Y7S6+KfpRVhIdYYXBIo
	6r7f8ik+zTXQ4wgnQfyHqoz2I5NN0CZA3EgRVaP/2OTF7iJ29bgkoOdnqxfBs5DM
	2f7Rz0+9/VyZ3TreocpXJ9e4rfyuy1ssQFrmQrRLUH+rCGIv6OI3+Myg3wrwbStD
	EO/b/5Cobhen4i9B2gUPyr7X1z1+Mied8H9LHw+JgSt2IsiRyLReWqumbSb91sqM
	zf2GdWWxAxVx+ofT7k1g4Z1kaVxSUBE/cczaTd3TgyIQut5PN4caEjKfxCyNLRdV
	5oqKF0ftAgMBAAECggEABj8uDepUOTfa+VWwk2KSMyq5zG+Vjey6gFjRBVLEAL6X
	e8Mdl6LhiIfM6p8kcHZ0X1BSimPcEINcLHRu+WrYOMK1/CzU0h2i5a3aGD9dliVp
	799LfL7KuingwwSC2y5ZcokAp+xszP5cGEpgMdiMlhCu2FgRLPalUmV75rzh6dQM
	0lUQGL8v9mCBdr2IxNUassYgFkLAxgAPK74vIfVXzWizXJs8p5nqBnUrz0rXedMk
	iZ1kyIAiye+CSRgPqE2pVzBMJ9SopmhXl/ikC0CNa+VEXIzIoYrY+ecWqkd6911O
	FtEbCqXsnYK1aDDvvd2iOECpqI4ld4HK0Ihis3soGwKBgQDnvWZN+hw62mxoaOMI
	Bax2x+LSWhlGKtwERLzJPHDK7PQ/nujN0fxWI/bSLke5fVdjSa8r7K0Ew9C5+lMo
	CNGjCyF14vFs72p9rq/bHod4mmFMDutK5LevySB89Mnq8QipO74xhQHO4BVil6d3
	xn6IhLTcGykbm1GL62hYcCJVOwKBgQDBel0m9Dk74mkeZ6gBzEhomostiy87PkZj
	Fg4umj+r27qYNO9ixNhNkrZ9SSrksKyCpPpeYxvfuTnreelIHQ3i9df5daLFtnr5
	w2yaVzec+y1JDRJI5Bl7STjuyKVGdzUtMIc2YkdgAHsQQQTzj6LOvHnEj3gum4dK
	G3QKJERk9wKBgQCph9133ikYxQHZwCGWlM/+dWxyBofG1UPvu3mAnj7FtWNZx574
	M04ullDSohjGkfOEJzuHHrXUbowcAg0jlJAIfvQTkdqcnumA2HK+Ei95Azd6tM9d
	EsVuS+0AfPPadEqpw5L4Fx2jgjsizV8uOIAIz0ygWR5Rm+akPaswR5hWUQKBgGA+
	l4IeMS5p9XKri7bBQS/P2PYh66/jza3SteFW19+M4Wh/xKl0VElady8hq5WxkU83
	9Ffpo18KTBaoQXSfB15kfzhX3U3O9aOzJB4uzrpndGKHfxYFaeubRBf8dcL0394H
	6usRvoGyG4W9YlIqnImM1mICIH3G3mjt+S5mViOHAoGADpcIrAILEBGbRDEqs0O3
	s5nReGuOtOUHmBKCAYGQ74WzEokrLzzn93b02uIfw6kFL+aCaJHRLTYoE5PuN5kS
	xeoNQxOYbRSVQGw86aDudmZqDkDHPp4G0XZ5/BtBlyvBQ4cgwMH13eY4wQGggRQM
	MmODDRzjD0e/A+/lPOCoUGQ=
	-----END PRIVATE KEY-----`);

	test('Verify public key', () => {
		assert.ok(publicKey instanceof CryptoKey, '`publicKey` should be a `CryptoKey`.');
		assert.ok(privateKey instanceof CryptoKey, '`privateKey` should be a `CryptoKey`.');
		assert.strictEqual(publicKey.type, 'public', '`publicKey` should be "public".');
		assert.strictEqual(privateKey.type, 'private', '`privateKey` should be "private".');
	});

	test('Verify signing & verifiying', async () => {
		const msg = new TextEncoder().encode('Hello, World!');
		const sig = await crypto.subtle.sign(ALGOS.RS256, privateKey, msg);
		const valid = await crypto.subtle.verify(ALGOS.RS256, publicKey, sig, msg);
		assert.ok(valid, 'Private key should sign and public key should verify signature.');
	});
});
