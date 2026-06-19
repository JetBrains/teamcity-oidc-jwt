# Google Cloud KMS signer for TeamCity OIDC JWT plugin

This TeamCity plugin provides a JWT signer implementation that uses Google Cloud KMS to sign JWTs.

## Supported key types
Currently, the plugin only supports RSA signing keys. This includes the following key types:
- `2048 bit RSA - PKCS#1 v1.5 padding - SHA256 digest` (`RS256`)
- `3072 bit RSA - PKCS#1 v1.5 padding - SHA256 digest` (`RS256`)
- `4096 bit RSA - PKCS#1 v1.5 padding - SHA256 digest` (`RS256`)
- `4096 bit RSA - PKCS#1 v1.5 padding - SHA512 digest` (`RS512`)
- `2048 bit RSA - PSS padding - SHA256 digest` (`PS256`)
- `3072 bit RSA - PSS padding - SHA256 digest` (`PS256`)
- `4096 bit RSA - PSS padding - SHA256 digest` (`PS256`)
- `4096 bit RSA - PSS padding - SHA512 digest` (`PS512`)

Note that `N bit raw RSA - PKCS#1 v1.5 padding` keys are not supported. 

Support for elliptic-curve keys is on the roadmap. Post-quantum keys are not supported because they are not included in the current version 
of the JWA specification at the time of writing (2026-04-13).

## Usage
1. Create a KMS key for asymmetric signing [as described in Google Cloud documentation](https://docs.cloud.google.com/kms/docs/create-key#create-asymmetric-sign)
2. Install and enable [TeamCity OIDC JWT plugin](../README.md)
3. Install and enable this plugin
4. Go to TeamCity settings → Integrations → OIDC Tokens
5. Under `Active Signer`, choose `Google Cloud KMS`
6. Provide the credentials to access the KMS key
7. Specify the KMS key resource name

## Supported resource types

### `CryptoKey`
Example resource name: `projects/PROJECT/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY`

Specifying a `CryptoKey` resource will use the first enabled key version returned by the KMS API.
There are no guarantees about which key version will be used if more than one enabled key version exists.

For this to work, the credentials used to access the KMS must have the following IAM permissions:
- `cloudkms.cryptoKeyVersions.list` (to choose the key version to use)
- `cloudkms.cryptoKeyVersions.useToSign` (to sign the JWT)
- `cloudkms.cryptoKeyVersions.viewPublicKey` (to get the public key for JWKS)

### `CryptoKeyVersion`
Example resource name: `projects/PROJECT/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY/cryptoKeyVersions/VERSION`

When `CryptoKeyVersion` is specified, this version will be used to sign the JWT. Disabling this version will break the
builds that use the OIDC JWT build feature.
