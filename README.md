# PHP Certificate Chain of Trust

This library provides a simple certificate and signature format built on top of [libsodium](https://www.php.net/manual/en/book.sodium.php) (Ed25519). It can be used to create certificate authorities, sign certificates, build chains and validate them.

## Installation

Install with [Composer](https://getcomposer.org/):

```bash
composer require kduma/cert-chain
```

## Creating a root CA

```php
use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Crypto\Ed25519;
use KDuma\CertificateChainOfTrust\DTO\{CertificateFlag, CertificateFlagsCollection, DescriptorType, Signature, UserDescriptor};

// Generate key pair for the root
$rootKey = Ed25519::makeKeyPair();

// Build the certificate and self-sign it
$rootCert = new Certificate(
    key: $rootKey,
    description: 'Example Root CA',
    userDescriptors: [new UserDescriptor(DescriptorType::DOMAIN, 'root.example')],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::ROOT_CA,
        CertificateFlag::CA,
        CertificateFlag::DOCUMENT_SIGNER,
    ]),
    signatures: []
);
$rootCert = $rootCert->with(
    signatures: [Signature::make($rootCert->toBinaryForSigning(), $rootKey)]
);
```

> **Note:** `ROOT_CA` by itself only marks a certificate as a trust anchor. To issue other certificates, the root must also carry the `CA` flag.

## Signing another certificate with the root CA

```php
// Generate key pair for the leaf certificate
$leafKey = Ed25519::makeKeyPair();

$leafCert = new Certificate(
    key: $leafKey,
    description: 'Leaf certificate',
    userDescriptors: [new UserDescriptor(DescriptorType::DOMAIN, 'service.example')],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::DOCUMENT_SIGNER,
    ]),
    signatures: []
);
// Signed by the root CA
$leafCert = $leafCert->with(
    signatures: [Signature::make($leafCert->toBinaryForSigning(), $rootKey)]
);
```

## Building and validating chains

```php
use KDuma\CertificateChainOfTrust\{Chain, TrustStore, Validator};

// Chain goes from leaf to root
$chain = new Chain([$leafCert, $rootCert]);

// Trust store containing trusted roots
$store = new TrustStore([$rootCert]);

$result = Validator::validateChain($chain, $store);
if (!$result->isValid) {
    throw new RuntimeException('Chain validation failed');
}
```

## Signing and verifying messages

```php
use KDuma\CertificateChainOfTrust\Utils\BinaryString;

$message = BinaryString::fromString('hello world');
$signature = Signature::make($message, $leafKey);

// Verify with the public key from the certificate
if (!$signature->validate($message, $leafCert->key)) {
    throw new RuntimeException('Invalid signature');
}
```

The `Certificate`, `Chain` and `TrustStore` classes can be serialized to binary and stored or transmitted using the `toBinary()` and `fromBinary()` helpers.

