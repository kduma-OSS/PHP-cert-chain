<?php declare(strict_types=1);

/**
 * PHP Certificate Chain of Trust - Comprehensive Examples
 *
 * This file demonstrates various usage patterns of the certificate chain library.
 * Run with: php examples.php
 */

use KDuma\BinaryTools\BinaryString;
use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Chain;
use KDuma\CertificateChainOfTrust\Crypto\Ed25519;
use KDuma\CertificateChainOfTrust\DTO\{
    CertificateFlag,
    CertificateFlagsCollection,
    DescriptorType,
    Signature,
    UserDescriptor
};
use KDuma\CertificateChainOfTrust\TrustStore;
use KDuma\CertificateChainOfTrust\Validator;

require __DIR__ . '/vendor/autoload.php';

echo "=== PHP Certificate Chain of Trust - Examples ===\n\n";

// =============================================================================
// Example 1: Basic Certificate Authority Setup
// =============================================================================

echo "1. Creating a Root Certificate Authority\n";
echo "----------------------------------------\n";

// Generate a key pair for the root CA
$rootKeyPair = Ed25519::makeKeyPair();

// Create the root certificate
$rootCA = new Certificate(
    key: $rootKeyPair->toPublicKey(),
    description: 'Example Root Certificate Authority',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'ca.example.com'),
        new UserDescriptor(DescriptorType::EMAIL, 'root-ca@example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::ROOT_CA,
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::CA,
        CertificateFlag::END_ENTITY_FLAG_1,  // Document signing capability
        CertificateFlag::END_ENTITY_FLAG_2,  // Code signing capability
        CertificateFlag::END_ENTITY_FLAG_3,  // Email encryption capability
    ]),
    signatures: []
);

// Self-sign the root certificate
$rootCA = $rootCA->with(
    signatures: [Signature::make($rootCA->toBinaryForSigning(), $rootKeyPair)]
);

echo "Root CA created:\n";
echo "- Description: {$rootCA->description}\n";
echo "- KeyId: {$rootCA->key->id->toString()}\n";
echo "- Flags: {$rootCA->flags->toString()}\n";
echo "- Self-signed: " . ($rootCA->isSelfSigned() ? 'Yes' : 'No') . "\n";
echo "- Is Root CA: " . ($rootCA->isRootCA() ? 'Yes' : 'No') . "\n\n";

// =============================================================================
// Example 2: Creating an Intermediate CA
// =============================================================================

echo "2. Creating an Intermediate Certificate Authority\n";
echo "-----------------------------------------------\n";

$intermediateKeyPair = Ed25519::makeKeyPair();

$intermediateCA = new Certificate(
    key: $intermediateKeyPair->toPublicKey(),
    description: 'Department Intermediate CA',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'dept-ca.example.com'),
        new UserDescriptor(DescriptorType::EMAIL, 'dept-ca@example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::CA,
        CertificateFlag::END_ENTITY_FLAG_1,  // Can delegate document signing
        CertificateFlag::END_ENTITY_FLAG_2,  // Can delegate code signing
        // Note: Cannot delegate END_ENTITY_FLAG_3 as it's not included
    ]),
    signatures: []
);

// Sign with the root CA
$intermediateCA = $intermediateCA->with(
    signatures: [Signature::make($intermediateCA->toBinaryForSigning(), $rootKeyPair)]
);

echo "Intermediate CA created:\n";
echo "- Description: {$intermediateCA->description}\n";
echo "- KeyId: {$intermediateCA->key->id->toString()}\n";
echo "- Flags: {$intermediateCA->flags->toString()}\n";
echo "- Signed by: Root CA\n\n";

// =============================================================================
// Example 3: Creating End-Entity Certificates
// =============================================================================

echo "3. Creating End-Entity Certificates\n";
echo "----------------------------------\n";

// Document signing certificate
$docSignerKeyPair = Ed25519::makeKeyPair();
$documentSigner = new Certificate(
    key: $docSignerKeyPair->toPublicKey(),
    description: 'Document Signing Certificate',
    userDescriptors: [
        new UserDescriptor(DescriptorType::USERNAME, 'john.doe'),
        new UserDescriptor(DescriptorType::EMAIL, 'john.doe@example.com'),
        new UserDescriptor(DescriptorType::DOMAIN, 'workstation.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::END_ENTITY_FLAG_1,  // Document signing only
    ]),
    signatures: []
);

// Sign with intermediate CA
$documentSigner = $documentSigner->with(
    signatures: [Signature::make($documentSigner->toBinaryForSigning(), $intermediateKeyPair)]
);

echo "Document Signer created:\n";
echo "- Description: {$documentSigner->description}\n";
echo "- KeyId: {$documentSigner->key->id->toString()}\n";
echo "- Flags: {$documentSigner->flags->toString()}\n";

// Code signing certificate
$codeSignerKeyPair = Ed25519::makeKeyPair();
$codeSigner = new Certificate(
    key: $codeSignerKeyPair->toPublicKey(),
    description: 'Code Signing Certificate',
    userDescriptors: [
        new UserDescriptor(DescriptorType::USERNAME, 'build.system'),
        new UserDescriptor(DescriptorType::EMAIL, 'build@example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::END_ENTITY_FLAG_2,  // Code signing only
    ]),
    signatures: []
);

$codeSigner = $codeSigner->with(
    signatures: [Signature::make($codeSigner->toBinaryForSigning(), $intermediateKeyPair)]
);

echo "Code Signer created:\n";
echo "- Description: {$codeSigner->description}\n";
echo "- KeyId: {$codeSigner->key->id->toString()}\n";
echo "- Flags: {$codeSigner->flags->toString()}\n\n";

// =============================================================================
// Example 4: Certificate Chain Validation
// =============================================================================

echo "4. Certificate Chain Validation\n";
echo "------------------------------\n";

// Create certificate chains
$documentChain = new Chain([$documentSigner, $intermediateCA, $rootCA]);
$codeSigningChain = new Chain([$codeSigner, $intermediateCA, $rootCA]);

// Create trust store
$trustStore = new TrustStore([$rootCA]);

echo "Trust store created with " . count($trustStore->certificates) . " root CA(s)\n";

// Validate document signing chain
echo "\nValidating document signing chain:\n";
$docResult = Validator::validateChain($documentChain, $trustStore);

if ($docResult->isValid) {
    echo "✓ Document signing chain is VALID\n";
    echo "  Validated chain has " . count($docResult->validatedChain) . " certificates\n";
} else {
    echo "✗ Document signing chain is INVALID\n";
    foreach ($docResult->getErrorMessages() as $error) {
        echo "  Error: $error\n";
    }
}

// Validate code signing chain
echo "\nValidating code signing chain:\n";
$codeResult = Validator::validateChain($codeSigningChain, $trustStore);

if ($codeResult->isValid) {
    echo "✓ Code signing chain is VALID\n";
    echo "  Validated chain has " . count($codeResult->validatedChain) . " certificates\n";
} else {
    echo "✗ Code signing chain is INVALID\n";
    foreach ($codeResult->getErrorMessages() as $error) {
        echo "  Error: $error\n";
    }
}

// =============================================================================
// Example 5: Invalid Certificate Scenarios
// =============================================================================

echo "\n5. Demonstrating Invalid Certificate Scenarios\n";
echo "---------------------------------------------\n";

// Example 5a: Invalid flag inheritance
echo "5a. Testing invalid flag inheritance:\n";
try {
    $invalidKeyPair = Ed25519::makeKeyPair();
    $invalidCert = new Certificate(
        key: $invalidKeyPair->toPublicKey(),
        description: 'Invalid Certificate - Wrong Flags',
        userDescriptors: [new UserDescriptor(DescriptorType::USERNAME, 'invalid.user')],
        flags: CertificateFlagsCollection::fromList([
            CertificateFlag::END_ENTITY_FLAG_3,  // Intermediate CA doesn't have this flag
        ]),
        signatures: []
    );

    $invalidCert = $invalidCert->with(
        signatures: [Signature::make($invalidCert->toBinaryForSigning(), $intermediateKeyPair)]
    );

    $invalidChain = new Chain([$invalidCert, $intermediateCA, $rootCA]);
    $invalidResult = Validator::validateChain($invalidChain, $trustStore);

    if (!$invalidResult->isValid) {
        echo "✓ Correctly rejected invalid flag inheritance:\n";
        foreach ($invalidResult->getErrorMessages() as $error) {
            echo "  Error: $error\n";
        }
    }
} catch (Exception $e) {
    echo "✓ Exception caught: " . $e->getMessage() . "\n";
}

// Example 5b: Duplicate KeyIds
echo "\n5b. Testing duplicate KeyIds:\n";
try {
    // Create a certificate with the same key as root CA (invalid)
    $duplicateKeyCert = new Certificate(
        key: $rootCA->key,  // Same key = same KeyId
        description: 'Certificate with Duplicate KeyId',
        userDescriptors: [new UserDescriptor(DescriptorType::USERNAME, 'duplicate')],
        flags: CertificateFlagsCollection::fromList([CertificateFlag::END_ENTITY_FLAG_1]),
        signatures: []
    );

    $duplicateKeyCert = $duplicateKeyCert->with(
        signatures: [Signature::make($duplicateKeyCert->toBinaryForSigning(), $rootKeyPair)]
    );

    $duplicateChain = new Chain([$duplicateKeyCert, $rootCA]);
    $duplicateResult = Validator::validateChain($duplicateChain, $trustStore);

    if (!$duplicateResult->isValid) {
        echo "✓ Correctly rejected duplicate KeyIds:\n";
        foreach ($duplicateResult->getErrorMessages() as $error) {
            echo "  Error: $error\n";
        }
    }
} catch (Exception $e) {
    echo "✓ Exception caught: " . $e->getMessage() . "\n";
}

// =============================================================================
// Example 6: Digital Signatures and Verification
// =============================================================================

echo "\n6. Digital Signatures and Message Verification\n";
echo "----------------------------------------------\n";

// Sign a document
$document = BinaryString::fromString("This is an important document that needs to be signed.");
$documentSignature = Signature::make($document, $docSignerKeyPair);

echo "Document signed with document signing certificate\n";
echo "Document content: " . $document->toString() . "\n";
echo "Signature created: " . bin2hex($documentSignature->toBinary()->value) . "\n";

// Verify the signature
$isValidSignature = $documentSignature->validate($document, $documentSigner->key);
echo "Signature verification: " . ($isValidSignature ? "✓ VALID" : "✗ INVALID") . "\n";

// Create a signed message structure
$signedMessage = [
    'message' => base64_encode($document->value),
    'signature' => base64_encode($documentSignature->toBinary()->value),
    'signer_keyid' => $documentSigner->key->id->toString(),
    'certificate_chain' => base64_encode($documentChain->toBinary()->value),
    'timestamp' => date('c'),
];

echo "\nSigned message structure created:\n";
echo "- Message size: " . strlen($document->value) . " bytes\n";
echo "- Signature size: " . strlen($documentSignature->toBinary()->value) . " bytes\n";
echo "- Signer KeyId: " . $signedMessage['signer_keyid'] . "\n";
echo "- Chain size: " . strlen($documentChain->toBinary()->value) . " bytes\n";
echo "- Timestamp: " . $signedMessage['timestamp'] . "\n";

// =============================================================================
// Example 7: Binary Serialization and Storage
// =============================================================================

echo "\n7. Binary Serialization and Storage\n";
echo "----------------------------------\n";

// Serialize certificates
$rootCertBinary = $rootCA->toBinary();
$chainBinary = $documentChain->toBinary();
$trustStoreBinary = $trustStore->toBinary();

echo "Serialization sizes:\n";
echo "- Root certificate: " . strlen($rootCertBinary->value) . " bytes\n";
echo "- Certificate chain: " . strlen($chainBinary->value) . " bytes\n";
echo "- Trust store: " . strlen($trustStoreBinary->value) . " bytes\n";

// Save to files (simulated)
echo "\nSaving to files (simulated):\n";
echo "- Saving root CA to 'root-ca.cert'\n";
echo "- Saving document chain to 'doc-chain.chain'\n";
echo "- Saving trust store to 'trust.store'\n";

// Load from binary (demonstration)
$loadedRootCA = Certificate::fromBinary($rootCertBinary);
$loadedChain = Chain::fromBinary($chainBinary);
$loadedTrustStore = TrustStore::fromBinary($trustStoreBinary);

echo "\nLoaded from binary:\n";
echo "- Root CA description: " . $loadedRootCA->description . "\n";
echo "- Chain certificates: " . count($loadedChain->certificates) . "\n";
echo "- Trust store roots: " . count($loadedTrustStore->certificates) . "\n";

// Verify loaded data integrity
$revalidationResult = Validator::validateChain($loadedChain, $loadedTrustStore);
echo "- Revalidation after load: " . ($revalidationResult->isValid ? "✓ VALID" : "✗ INVALID") . "\n";

// =============================================================================
// Example 8: Advanced Certificate Hierarchies
// =============================================================================

echo "\n8. Advanced Certificate Hierarchies\n";
echo "----------------------------------\n";

// Create a specialized policy CA
$policyKeyPair = Ed25519::makeKeyPair();
$policyCA = new Certificate(
    key: $policyKeyPair->toPublicKey(),
    description: 'Security Policy CA',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'policy-ca.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::CA,
        CertificateFlag::END_ENTITY_FLAG_1,  // Must be subset of root's flags
        CertificateFlag::END_ENTITY_FLAG_2,  // Must be subset of root's flags
    ]),
    signatures: []
);

$policyCA = $policyCA->with(
    signatures: [Signature::make($policyCA->toBinaryForSigning(), $rootKeyPair)]
);

// Create a server authentication certificate
$serverKeyPair = Ed25519::makeKeyPair();
$serverCert = new Certificate(
    key: $serverKeyPair->toPublicKey(),
    description: 'Web Server Certificate',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'api.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::END_ENTITY_FLAG_2,  // Server authentication (subset of policy CA)
    ]),
    signatures: []
);

$serverCert = $serverCert->with(
    signatures: [Signature::make($serverCert->toBinaryForSigning(), $policyKeyPair)]
);

// Validate the server certificate chain
$serverChain = new Chain([$serverCert, $policyCA, $rootCA]);
$serverResult = Validator::validateChain($serverChain, $trustStore);

echo "Server certificate chain validation:\n";
if ($serverResult->isValid) {
    echo "✓ Server certificate chain is VALID\n";
} else {
    echo "✗ Server certificate chain is INVALID\n";
    foreach ($serverResult->getErrorMessages() as $error) {
        echo "  Error: $error\n";
    }
}

// =============================================================================
// Example 9: Multi-Purpose Certificates
// =============================================================================

echo "\n9. Multi-Purpose Certificates\n";
echo "----------------------------\n";

// Create a certificate with multiple capabilities
$multiPurposeKeyPair = Ed25519::makeKeyPair();
$multiPurposeCert = new Certificate(
    key: $multiPurposeKeyPair->toPublicKey(),
    description: 'Multi-Purpose Certificate',
    userDescriptors: [
        new UserDescriptor(DescriptorType::USERNAME, 'admin.user'),
        new UserDescriptor(DescriptorType::EMAIL, 'admin@example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::END_ENTITY_FLAG_1,  // Document signing
        CertificateFlag::END_ENTITY_FLAG_2,  // Code signing
        // Note: Can only use flags that intermediate CA has
    ]),
    signatures: []
);

$multiPurposeCert = $multiPurposeCert->with(
    signatures: [Signature::make($multiPurposeCert->toBinaryForSigning(), $intermediateKeyPair)]
);

echo "Multi-purpose certificate created:\n";
echo "- Description: {$multiPurposeCert->description}\n";
echo "- Capabilities: {$multiPurposeCert->flags->toString()}\n";

// Test different usage scenarios
echo "\nTesting certificate capabilities:\n";
echo "- Can sign documents: " . ($multiPurposeCert->flags->has(CertificateFlag::END_ENTITY_FLAG_1) ? "Yes" : "No") . "\n";
echo "- Can sign code: " . ($multiPurposeCert->flags->has(CertificateFlag::END_ENTITY_FLAG_2) ? "Yes" : "No") . "\n";
echo "- Can encrypt emails: " . ($multiPurposeCert->flags->has(CertificateFlag::END_ENTITY_FLAG_3) ? "Yes" : "No") . "\n";

// =============================================================================
// Example 10: Performance and Best Practices
// =============================================================================

echo "\n10. Performance and Best Practices\n";
echo "---------------------------------\n";

$startTime = microtime(true);

// Batch certificate creation
echo "Creating 100 certificates...\n";
$certificates = [];
for ($i = 0; $i < 100; $i++) {
    $keyPair = Ed25519::makeKeyPair();
    $cert = new Certificate(
        key: $keyPair->toPublicKey(),
        description: "Test Certificate #" . ($i + 1),
        userDescriptors: [
            new UserDescriptor(DescriptorType::USERNAME, "user{$i}"),
        ],
        flags: CertificateFlagsCollection::fromList([
            CertificateFlag::END_ENTITY_FLAG_1,
        ]),
        signatures: []
    );

    $cert = $cert->with(
        signatures: [Signature::make($cert->toBinaryForSigning(), $intermediateKeyPair)]
    );

    $certificates[] = $cert;
}

$creationTime = microtime(true) - $startTime;
echo "Certificate creation completed in " . number_format($creationTime * 1000, 2) . " ms\n";

// Batch validation
$validationStart = microtime(true);
$validCount = 0;

foreach ($certificates as $cert) {
    $testChain = new Chain([$cert, $intermediateCA, $rootCA]);
    $result = Validator::validateChain($testChain, $trustStore);
    if ($result->isValid) {
        $validCount++;
    }
}

$validationTime = microtime(true) - $validationStart;
echo "Validated $validCount/" . count($certificates) . " certificates in " .
     number_format($validationTime * 1000, 2) . " ms\n";
echo "Average validation time: " .
     number_format(($validationTime / count($certificates)) * 1000, 2) . " ms per certificate\n";

// Memory usage
echo "Peak memory usage: " . number_format(memory_get_peak_usage(true) / 1024 / 1024, 2) . " MB\n";

// =============================================================================
// Summary
// =============================================================================

echo "\n=== Summary ===\n";
echo "This examples file demonstrated:\n";
echo "1. ✓ Basic root CA and certificate creation\n";
echo "2. ✓ Intermediate CA setup and hierarchies\n";
echo "3. ✓ End-entity certificate creation with specific capabilities\n";
echo "4. ✓ Certificate chain validation\n";
echo "5. ✓ Error handling for invalid certificates\n";
echo "6. ✓ Digital signature creation and verification\n";
echo "7. ✓ Binary serialization and data persistence\n";
echo "8. ✓ Advanced certificate hierarchies\n";
echo "9. ✓ Multi-purpose certificates with multiple flags\n";
echo "10. ✓ Performance considerations and batch operations\n\n";

echo "For detailed API documentation, see DOCS.md\n";
echo "For basic usage, see README.md\n";

// Helper function for message verification (bonus example)
function verifySignedMessage(array $signedMessage, TrustStore $trustStore): bool
{
    try {
        // Reconstruct message components
        $message = BinaryString::fromString(base64_decode($signedMessage['message']));
        $signature = Signature::fromBinary(BinaryString::fromString(base64_decode($signedMessage['signature'])));
        $chain = Chain::fromBinary(BinaryString::fromString(base64_decode($signedMessage['certificate_chain'])));

        // Validate certificate chain
        $chainResult = Validator::validateChain($chain, $trustStore);
        if (!$chainResult->isValid) {
            return false;
        }

        // Find signer certificate by KeyId
        $signerKeyId = $signedMessage['signer_keyid'];
        $signerCert = null;
        foreach ($chain->certificates as $cert) {
            if ($cert->key->id->toString() === $signerKeyId) {
                $signerCert = $cert;
                break;
            }
        }

        if (!$signerCert) {
            return false;
        }

        // Verify signature
        return $signature->validate($message, $signerCert->key);

    } catch (Exception $e) {
        return false;
    }
}

echo "\n=== Example Complete ===\n";
