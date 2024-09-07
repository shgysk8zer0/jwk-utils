<!-- markdownlint-disable -->
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
