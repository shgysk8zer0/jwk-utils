<!-- markdownlint-disable -->
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.0.20] - 2024-12-20

### Fixed
- Fixed generating `kid` to match what's using in `jwt.header.kid` in `exportAsRFC7517JWK()`

## [v1.0.19] - 2024-12-20

### Added
- Add support for RFC7517 imports and exports of keys
- Add conversion of `Date` objects to Unix timestamps for certain claims

## [v1.0.18] - 2024-12-17

### Added
- Add function to fetch & import key(s) from `.well-known/jwks.json`
- Add function to verify JWTs by issuer (`iss`) using key from `.well-known/jwks.json`

## [v1.0.17] - 2024-12-09

### Added
- Add support for bypassing role/entitlements check if same owner (`sub` by default)
- Add support for bypassing `entitlements` check based on `roles`
- Add function to get current Firebase public key

### Changed
- `decodeToken()` now only decodes, without checking claims
- Update `verifyJWT` to support owner of resource bypassing permissions/roles
- Tests to pass with recent changes
- Use `@shgysk8zer0/eslint-config`

## [v1.0.16] - 2024-09-28

### Fixed
- Run `npm audit fix` to fix CVE-2024-43788

## [v1.0.15] - 2024-09-17

### Changed
- Update `@shgysk8zer0/polyfills` with improved support for node

## [v1.0.14] - 2024-09-12

### Fixed
- Fix/update JSDocs documentation

## [v1.0.13] - 2024-09-12

### Added
- Add `getSigningKey` and `getVerifyingKey`
- Extend testing to cover all functions (func coverage = 92.11%)
- Add optional `claims` check to `verifyPayload`
- Add `refreshJWT` to update `iss` and `exp` of tokens

### Changed
- Rename `decodeOriginToken` -> `verifyOriginToken` & `verifyOriginToken` -> `verifyRequestOriginToken`

## [v1.0.12] - 2024-09-10

### Removed
- Do not load `@shgysk8zer0/polyfills` except in `main`/`module`/`jwk-utils` due to conflicts

## [v1.0.11] - 2024-09-10

### Added
- Add `verifySignature` function to normalize this

### Fixed
- Fix `iat`, `exp` checks

## [v1.0.10] - 2024-09-08

### Added
- Add `hasEntitlements` to verify `entitlements` of decoded JWT

### Changed
- Use `node:test` & `node:assert` / `node --test` instead of own basic tests

### Fixed
- Fix passing `leeway` and `entitlemenets` in `verifyJWT` when passed CryptokeyPair


## [v1.0.9] - 2024-09-07

## Added
- Add optional checks for `entitlements`/JWT permissions
- Add support for importing from raw

## [v1.0.8] - 2024-09-05

### Added
- Add `exportJWK`

### Fixed
- Fix bad check & error in `importJWK`

## [v1.0.7] - 2024-09-04

## Added
- Add `createJWKBlob` in addition to `createJWKFile`

### Changed
- Improve debugging by returning `Error`s
- Rename `loadJWKFromFile` to `loadJWKFromBlob` (supports both, as `File` extends `Blob`)

## [v1.0.6] - 2024-09-02

### Added
- Create `.map` files for generated `.min.js` modules
- Add `verifyHeader` and `verifyPayload` for verifying decoded JWTs

### Changed
- JWT generating and verifying functions can now take either a `CryptoKey` or `CryptoKeyPair`

### Fixed
- Fixed bad `payload.exp` check

## [v1.0.5] - 2024-09-01

### Fixed
- Fix marking `generateJWKPair` (`createJWT` is not deprecated)

## [v1.0.4] - 2024-09-01

### Added
- Added support for HS256, HS384, HS512, PS256, PS384, PS512, and EdDSA

### Deprecated
- Deprecate `generateJWKPair` (use `generateJWK` instead... It's no longer always a key pair)

## [v1.0.3] - 2024-08-31

### Added
- Added support for RS384, RS512, ES384, and ES512 algorithms

### Fixed
- Fix incorrect base64 encoding

## [v1.0.2] - 2024-08-31

### Fixed
- Fix typo in "Authorization" constant

## [v1.0.1] - 2024-08-31

### Fixed
- Ensure failed decoding of tokens does not throw.

## [v1.0.0] - 2024-08-30

Initial Release
