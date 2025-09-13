# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

### Testing
- `./vendor/bin/phpunit` - Run all tests
- `./vendor/bin/phpunit tests/ValidatorTest.php` - Run specific test class
- `composer test` - Run all tests (alias)
- `composer test-coverage` - Generate HTML coverage report in `coverage/` directory

### Development
- `composer install` - Install dependencies
- `composer dump-autoload` - Regenerate autoloader

## Architecture Overview

This is a PHP library implementing a certificate chain of trust system with Ed25519 cryptography. The architecture follows a layered approach:

### Core Components

**Certificate (`src/Certificate.php`)**
- Main certificate class representing a single certificate with public key, description, user descriptors, flags, and signatures
- Implements binary serialization/deserialization following the specification in `SPECIFICATION.md`
- Contains validation logic for self-signing and certificate structure

**Chain (`src/Chain.php`) and TrustStore (`src/TrustStore.php`)**
- Both extend `CertificatesContainer` but serve different purposes
- `Chain`: Contains certificates to be validated, allows any certificate type
- `TrustStore`: Contains only trusted root CA certificates, enforces root CA validation

**Validator (`src/Validator.php`)**
- Core validation logic implementing certificate chain validation
- Contains complex validation rules including:
  - Certificate Authority validation (CA flags must have proper signing authority)
  - End-entity flag inheritance (child certificates inherit limitations from parent)
  - Cryptographic signature verification
  - Trust store validation

### Flag-Based Security Model

The system implements a hierarchical certificate authority model using flags (`src/DTO/CertificateFlag.php`):

- `ROOT_CA` (0x0001): Self-signed root certificate authorities
- `INTERMEDIATE_CA` (0x0002): Enables signing of CA-level certificates when combined with `CA`
- `CA` (0x0004): Required to sign any certificate; alone it can sign only end-entity (non-CA) certificates
- `DOCUMENT_SIGNER` (0x0100): Can sign documents
- `TEMPLATE_SIGNER` (0x0200): Can sign templates

**Key Validation Rules:**
- Signers must have `CA` to issue any certificates
- Signing a certificate with CA-level flags additionally requires `INTERMEDIATE_CA`
- End-entity flags (`DOCUMENT_SIGNER`, `TEMPLATE_SIGNER`) must be a subset of the signer's flags
- `ROOT_CA` certificates must be self-signed

### Directory Structure

- `src/Crypto/`: Ed25519 cryptographic operations, key management
- `src/DTO/`: Data transfer objects for validation results, certificate flags, user descriptors
- `src/Utils/`: Binary serialization utilities for certificate encoding/decoding
- `tests/`: PHPUnit test suite with comprehensive validation test cases

### Testing Strategy

The test suite (`tests/ValidatorTest.php`) uses a `makeTestCert` helper method to create certificates dynamically rather than hardcoded test data. This ensures tests exercise the actual cryptographic operations and certificate relationships.

Key test patterns:
- Create certificate hierarchies using `makeTestCert('name', [flags], [signers])`
- Build chains with `new Chain([leaf, intermediate, root])`
- Validate using `Validator::validateChain($chain, $trustStore)`

### Binary Format

Certificates follow a custom binary format specified in `SPECIFICATION.md`:
- Magic bytes: `08 44 53` ("CERT" in base64)
- Ed25519 keys and signatures (fixed 32/64 byte lengths)
- UTF-8 strings with length prefixes
- Big-endian multi-byte integers

The `examples.php` file contains pre-generated test certificates and demonstrates library usage.

## Development Notes

- PHP 8.4+ required with extensions: mbstring, hash, sodium
- Uses PSR-4 autoloading with namespace `KDuma\CertificateChainOfTrust`
- Heavy use of readonly classes and modern PHP features
- Comprehensive error handling with descriptive validation error messages