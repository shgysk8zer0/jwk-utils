# @shgysk8zer0/jwk-utils

Use JWK and JWTs using the Crypto API

[![CodeQL](https://github.com/shgysk8zer0/jwk-utils/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/shgysk8zer0/jwk-utils/actions/workflows/codeql-analysis.yml)
![Node CI](https://github.com/shgysk8zer0/jwk-utils/workflows/Node%20CI/badge.svg)
![Lint Code Base](https://github.com/shgysk8zer0/jwk-utils/workflows/Lint%20Code%20Base/badge.svg)

[![GitHub license](https://img.shields.io/github/license/shgysk8zer0/jwk-utils.svg)](https://github.com/shgysk8zer0/jwk-utils/blob/master/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/shgysk8zer0/jwk-utils.svg)](https://github.com/shgysk8zer0/jwk-utils/commits/master)
[![GitHub release](https://img.shields.io/github/release/shgysk8zer0/jwk-utils?logo=github)](https://github.com/shgysk8zer0/jwk-utils/releases)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/shgysk8zer0?logo=github)](https://github.com/sponsors/shgysk8zer0)

[![npm](https://img.shields.io/npm/v/@shgysk8zer0/jwk-utils)](https://www.npmjs.com/package/@shgysk8zer0/jwk-utils)
![node-current](https://img.shields.io/node/v/@shgysk8zer0/jwk-utils)
![npm bundle size gzipped](https://img.shields.io/bundlephobia/minzip/@shgysk8zer0/jwk-utils)
[![npm](https://img.shields.io/npm/dw/@shgysk8zer0/jwk-utils?logo=npm)](https://www.npmjs.com/package/@shgysk8zer0/jwk-utils)

[![GitHub followers](https://img.shields.io/github/followers/shgysk8zer0.svg?style=social)](https://github.com/shgysk8zer0)
![GitHub forks](https://img.shields.io/github/forks/shgysk8zer0/jwk-utils.svg?style=social)
![GitHub stars](https://img.shields.io/github/stars/shgysk8zer0/jwk-utils.svg?style=social)
[![Twitter Follow](https://img.shields.io/twitter/follow/shgysk8zer0.svg?style=social)](https://twitter.com/shgysk8zer0)

[![Donate using Liberapay](https://img.shields.io/liberapay/receives/shgysk8zer0.svg?logo=liberapay)](https://liberapay.com/shgysk8zer0/donate "Donate using Liberapay")
- - -

- [Code of Conduct](./.github/CODE_OF_CONDUCT.md)
- [Contributing](./.github/CONTRIBUTING.md)


## Installation

```bash
npm i @shgysk8zer0/jwk-utils
```

## About
This library provides [JWK](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#json_web_key)
and [JWT](https://jwt.io/) support via the [`crypto` API](https://developer.mozilla.org/en-US/docs/Web/API/Crypto).

### Supported Algorithms
- RS256
- ES256

### Example

```js
import { generateJWKPair, createJWT, verifyJWT } from '@shgysk8zer0/jwt-jwk';

// Generate a JWK pair
const { publicKey, privateKey } = await generateJWKPair();

// Create a JWT
const token = await createJWT({ data: 'some payload' }, privateKey);

// Verify the JWT
const verifiedPayload = await verifyJWT(token, publicKey);
```

## Limitations

Due to using JWKs and public/private keys, this currently does not support HS256
or any symmetric keys.
