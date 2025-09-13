# PHP Certificate Chain of Trust

[![Latest Version on Packagist](https://img.shields.io/packagist/v/kduma/cert-chain.svg?style=flat-square)](https://packagist.org/packages/kduma/cert-chain)
[![Tests](https://img.shields.io/github/actions/workflow/status/kduma-OSS/PHP-cert-chain/tests.yml?branch=master&label=tests&style=flat-square)](https://github.com/kduma-OSS/PHP-cert-chain/actions/workflows/tests.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/kduma/cert-chain.svg?style=flat-square)](https://packagist.org/packages/kduma/cert-chain)

A modern, secure PHP library for creating and managing certificate authorities, digital signatures, and trust relationships using **Ed25519 cryptography**. Built for PHP 8.4+ with strict typing, immutable objects, and comprehensive validation.

Check full documentation: [opensource.duma.sh/libraries/php/cert-chain](https://opensource.duma.sh/libraries/php/cert-chain)

## ✨ Key Features

- 🔐 **Ed25519 Cryptography**: Fast, secure elliptic curve signatures via libsodium
- 📜 **Flexible Certificate System**: Generic end-entity flags for maximum reusability
- 🏗️ **Hierarchical Trust**: Root CAs, intermediate CAs, and end-entity certificates
- 🔍 **Strict Validation**: Comprehensive security checks and flag inheritance validation
- 💾 **Binary Format**: Efficient serialization for storage and transmission
- 🛡️ **Security-First**: Unique KeyId validation, proper certificate chain verification
- 🚀 **Modern PHP**: Built for PHP 8.4+ with readonly classes and strict typing

## 📦 Installation

Install with [Composer](https://getcomposer.org/):

```bash
composer require kduma/cert-chain
```

**Requirements:**
- PHP 8.4+
- Extensions: `ext-sodium`, `ext-hash`, `ext-mbstring`

## 🚀 Quick Start

### Create a Root Certificate Authority

```php
<?php
use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Crypto\Ed25519;
use KDuma\CertificateChainOfTrust\DTO\{
    CertificateFlag,
    CertificateFlagsCollection,
    DescriptorType,
    Signature,
    UserDescriptor
};

// Generate a key pair for the root CA
$rootKeyPair = Ed25519::makeKeyPair();

// Create and self-sign the root certificate
$rootCA = new Certificate(
    key: $rootKeyPair->toPublicKey(),
    description: 'My Root Certificate Authority',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'ca.example.com'),
        new UserDescriptor(DescriptorType::EMAIL, 'admin@example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::ROOT_CA,           // Self-signed root
        CertificateFlag::INTERMEDIATE_CA,   // Can sign other CAs
        CertificateFlag::CA,               // Can sign end-entity certs
        CertificateFlag::END_ENTITY_FLAG_1, // Generic capability 1
        CertificateFlag::END_ENTITY_FLAG_2, // Generic capability 2
    ]),
    signatures: []
);

// Self-sign the certificate
$rootCA = $rootCA->with(
    signatures: [Signature::make($rootCA->toBinaryForSigning(), $rootKeyPair)]
);
```

### Create and Sign an End-Entity Certificate

```php
// Generate key pair for end-entity certificate
$leafKeyPair = Ed25519::makeKeyPair();

$leafCert = new Certificate(
    key: $leafKeyPair->toPublicKey(),
    description: 'Document Signing Certificate',
    userDescriptors: [
        new UserDescriptor(DescriptorType::USERNAME, 'john.doe'),
        new UserDescriptor(DescriptorType::EMAIL, 'john.doe@example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::END_ENTITY_FLAG_1, // Must be subset of signer's flags
    ]),
    signatures: []
);

// Sign with the root CA
$leafCert = $leafCert->with(
    signatures: [Signature::make($leafCert->toBinaryForSigning(), $rootKeyPair)]
);
```

### Validate Certificate Chains

```php
use KDuma\CertificateChainOfTrust\{Chain, TrustStore, Validator};

// Create certificate chain (leaf to root)
$chain = new Chain([$leafCert, $rootCA]);

// Create trust store with trusted root CAs
$trustStore = new TrustStore([$rootCA]);

// Validate the chain
$result = Validator::validateChain($chain, $trustStore);

if ($result->isValid) {
    echo "✅ Certificate chain is valid!\n";
    echo "Validated " . count($result->validatedChain) . " certificates\n";
} else {
    echo "❌ Validation failed:\n";
    foreach ($result->getErrorMessages() as $error) {
        echo "- $error\n";
    }
}
```

### Sign and Verify Messages

```php
use KDuma\BinaryTools\BinaryString;

// Sign a message
$message = BinaryString::fromString('Important document content');
$signature = Signature::make($message, $leafKeyPair);

// Verify the signature
$isValid = $signature->validate($message, $leafCert->key);
echo $isValid ? "✅ Signature valid" : "❌ Signature invalid";
```

## 🏗️ Certificate Flag System

The library uses a flexible flag system for maximum reusability:

### CA-Level Flags
- `ROOT_CA` (0x0001): Self-signed root certificate authority
- `INTERMEDIATE_CA` (0x0002): Can sign CA-level certificates
- `CA` (0x0004): Can sign end-entity certificates

### Generic End-Entity Flags
- `END_ENTITY_FLAG_1` through `END_ENTITY_FLAG_8` (0x0100-0x8000)
- Use these for any purpose: document signing, code signing, email encryption, etc.
- **Flag Inheritance**: Certificate flags must be a subset of the signer's flags

## 🔐 Security Model

- **Unique KeyIds**: All certificates in a chain must have unique identifiers
- **Flag Inheritance**: End-entity flags are inherited down the chain (strict subset rule)
- **Proper Authority**: CA flags determine what types of certificates can be signed
- **Cryptographic Verification**: Ed25519 signatures with full chain validation
- **Trust Anchors**: Only certificates in the TrustStore are trusted

## 📚 Documentation

- **[Documentation](https://opensource.duma.sh/libraries/php/cert-chain#table-of-contents)** - Complete API documentation and advanced usage
- **[examples.php](examples.php)** - Comprehensive examples and use cases
- **[Specification](https://opensource.duma.sh/libraries/php/cert-chain#common-rules)** - Binary format and protocol specification

## 🔧 Advanced Features

### Binary Serialization
```php
// Serialize for storage/transmission
$binaryData = $certificate->toBinary();
$chainData = $chain->toBinary();
$trustStoreData = $trustStore->toBinary();

// Load from binary
$loadedCert = Certificate::fromBinary($binaryData);
$loadedChain = Chain::fromBinary($chainData);
```

### Complex Hierarchies
```php
// Multi-level certificate hierarchies
$rootCA = createRootCA();
$policyCA = createPolicyCA($rootCA);
$issuingCA = createIssuingCA($policyCA);
$endEntity = createEndEntity($issuingCA);

$chain = new Chain([$endEntity, $issuingCA, $policyCA, $rootCA]);
```

### Batch Operations
```php
// Efficient validation of multiple certificates
foreach ($certificates as $cert) {
    $result = Validator::validateChain(
        new Chain([$cert, $intermediateCA, $rootCA]),
        $trustStore
    );
    // Process result...
}
```

## 🧪 Development

```bash
# Run tests
composer test

# Generate coverage report
composer test-coverage

# Check code style
composer lint

# Fix code style
composer fix
```

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please see the examples and documentation to understand the library architecture.

---

**🔗 Related Projects:**
- [kduma/binary-tools](https://opensource.duma.sh/libraries/php/binary-tools) - Binary data manipulation utilities

