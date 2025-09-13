<?php

namespace KDuma\CertificateChainOfTrust\Tests;

use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Chain;
use KDuma\CertificateChainOfTrust\Crypto\Ed25519;
use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PublicKey;
use KDuma\CertificateChainOfTrust\DTO\CertificateFlag;
use KDuma\CertificateChainOfTrust\DTO\CertificateFlagsCollection;
use KDuma\CertificateChainOfTrust\DTO\DescriptorType;
use KDuma\CertificateChainOfTrust\DTO\Signature;
use KDuma\CertificateChainOfTrust\DTO\UserDescriptor;
use KDuma\CertificateChainOfTrust\DTO\ValidationError;
use KDuma\CertificateChainOfTrust\DTO\ValidationResult;
use KDuma\CertificateChainOfTrust\DTO\ValidationWarning;
use KDuma\CertificateChainOfTrust\TrustStore;
use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use KDuma\CertificateChainOfTrust\Validator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Validator::class)]
class ValidatorTest extends TestCase
{

    protected array $certificates = [];
    protected function setUp(): void
    {
        parent::setUp();
        $this->certificates = [];
    }

    protected function makeTestCert(string $name, array $flags, array $signed_by): Certificate {
        $this->certificates[$name] = [
            'key' => Ed25519::makeKeyPair(),
            'certificate' => null,
        ];

        $this->certificates[$name]['certificate'] = new Certificate(
            key: $this->certificates[$name]['key']->toPublicKey(),
            description: $name,
            userDescriptors: [
                new UserDescriptor(DescriptorType::USERNAME, $name),
            ],
            flags: CertificateFlagsCollection::fromList($flags),
            signatures: []
        );
        $signatures = [];
        foreach ($signed_by as $signerName) {
            if (!isset($this->certificates[$signerName])) {
                throw new \InvalidArgumentException("Signer certificate '$signerName' not found for '$name'");
            }
            $signatures[] = Signature::make($this->certificates[$name]['certificate']->toBinaryForSigning(), $this->certificates[$signerName]['key']);
        }
        $this->certificates[$name]['certificate'] = $this->certificates[$name]['certificate']->with(signatures:$signatures);

        return $this->certificates[$name]['certificate'];
    }

    private function invokeValidatePath(array $path, TrustStore $store): array
    {
        $ref = new \ReflectionClass(Validator::class);
        $m = $ref->getMethod('validatePath');
        $m->setAccessible(true);
        return $m->invoke(null, $path, $store);
    }

    public function testValidateCompleteValidChain()
    {
        // Create complete certificate chain using makeTestCert
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $ca = $this->makeTestCert('ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['ca']);

        $chain = new Chain([
            $signer,
            $ca,
            $intermediate_ca,
            $root_ca,
        ]);

        // Create trust store with root CA
        $trustStore = new TrustStore([
            $root_ca,
        ]);

        // Validate the chain using static method
        $result = Validator::validateChain($chain, $trustStore);
        if (!$result->isValid) {
            $this->fail("Unexpected invalid result: " . implode(" | ", $result->getErrorMessages()));
        }

        // Assert successful validation
        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertTrue($result->isValid);
        $this->assertCount(0, $result->errors);
        $this->assertCount(0, $result->warnings);
        $this->assertCount(4, $result->validatedChain);

        // Verify validated chain contains correct certificates in correct order
        $this->assertEquals($signer->key->id->toHex(), $result->validatedChain[0]->key->id->toHex());
        $this->assertEquals($ca->key->id->toHex(), $result->validatedChain[1]->key->id->toHex());
        $this->assertEquals($intermediate_ca->key->id->toHex(), $result->validatedChain[2]->key->id->toHex());
        $this->assertEquals($root_ca->key->id->toHex(), $result->validatedChain[3]->key->id->toHex());
    }

    public function testValidateEmptyChain()
    {
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        
        $emptyChain = new Chain([]);
        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($emptyChain, $trustStore);

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid);
        $this->assertCount(1, $result->errors);
        $this->assertCount(0, $result->warnings);
        $this->assertCount(0, $result->validatedChain);

        $errorMessages = $result->getErrorMessages();
        $this->assertEquals('No certificates in chain to validate', $errorMessages[0]);
    }

    public function testValidateIncompleteChain()
    {
        // Create certificates but use incomplete chain (missing intermediate and root CA)
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $ca = $this->makeTestCert('ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['ca']);
        
        $incompleteChain = new Chain([
            $signer,
            $ca,
            // Missing intermediate CA and root CA
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($incompleteChain, $trustStore);

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid);
        $this->assertCount(1, $result->errors);
        $this->assertCount(0, $result->warnings);
        $this->assertCount(0, $result->validatedChain);

        $errorMessages = $result->getErrorMessages();
        $this->assertStringContainsString('No complete certification path found', $errorMessages[0]);
        $this->assertStringContainsString('Certificate: ' . $signer->key->id->toHex(), $errorMessages[0]);
        $this->assertStringContainsString('[path building]', $errorMessages[0]);
    }

    public function testValidateRootNotInTrustStore()
    {
        // Create complete valid chain
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $ca = $this->makeTestCert('ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['ca']);
        
        $chain = new Chain([
            $signer,
            $ca,
            $intermediate_ca,
            $root_ca,
        ]);

        // Create empty trust store (root CA not trusted)
        $emptyTrustStore = new TrustStore([]);

        $result = Validator::validateChain($chain, $emptyTrustStore);

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid);
        $this->assertCount(2, $result->errors); // Main error + path validation error
        $this->assertCount(0, $result->warnings);
        $this->assertCount(0, $result->validatedChain);

        $errorMessages = $result->getErrorMessages();
        $this->assertStringContainsString('No valid certification path found', $errorMessages[0]);
        $this->assertStringContainsString('Root CA is not in the trust store', $errorMessages[1]);
        $this->assertStringContainsString('Certificate: ' . $root_ca->key->id->toHex(), $errorMessages[1]);
        $this->assertStringContainsString('[trust store validation]', $errorMessages[1]);
    }

    public function testValidateChainAcceptsCertificatesWithValidKeyIds()
    {
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $ca = $this->makeTestCert('ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['ca']);

        $chain = new Chain([
            $signer,
            $ca,
            $intermediate_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertTrue(
            $result->isValid,
            'Unexpected invalid: ' . implode(' | ', $result->getErrorMessages())
        );
    }

    public function testValidateChainRejectsCertificatesWithMismatchedKeyId()
    {
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $ca = $this->makeTestCert('ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['ca']);

        $bad_signer = $signer->with(
            key: new PublicKey(
                KeyId::fromHex('00000000000000000000000000000000'),
                $signer->key->publicKey,
            )
        );

        $chain = new Chain([
            $bad_signer,
            $ca,
            $intermediate_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);

        $this->assertFalse($result->isValid);
        $errorMessages = $result->getErrorMessages();
        $this->assertStringContainsString('KeyId does not match public key', $errorMessages[1]);
    }

    public function testValidateChainRejectsCertificatesWithoutSignatures()
    {
        $unsigned = $this->makeTestCert('unsigned', [CertificateFlag::DOCUMENT_SIGNER], []);

        $chain = new Chain([
            $unsigned,
        ]);

        $trustStore = new TrustStore([]);

        $result = Validator::validateChain($chain, $trustStore);

        $this->assertFalse($result->isValid);
        $this->assertCount(1, $result->errors);
        $this->assertStringContainsString('Certificate has no signatures', $result->getErrorMessages()[0]);
    }

    public function testValidationResultStructure()
    {
        // Test with valid chain using makeTestCert
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $ca = $this->makeTestCert('ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['ca']);
        
        $validChain = new Chain([
            $signer,
            $ca,
            $intermediate_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($validChain, $trustStore);
        $this->assertTrue(
            $result->isValid,
            'Unexpected invalid: ' . implode(' | ', $result->getErrorMessages())
        );

        // Test result structure and types
        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertIsBool($result->isValid);
        $this->assertIsArray($result->errors);
        $this->assertIsArray($result->warnings);
        $this->assertIsArray($result->validatedChain);

        // Test that all array elements are of correct type
        foreach ($result->errors as $error) {
            $this->assertInstanceOf(ValidationError::class, $error);
        }

        foreach ($result->warnings as $warning) {
            $this->assertInstanceOf(ValidationWarning::class, $warning);
        }

        foreach ($result->validatedChain as $cert) {
            $this->assertInstanceOf(Certificate::class, $cert);
        }

        // Test error/warning message methods
        $this->assertIsArray($result->getErrorMessages());
        $this->assertIsArray($result->getWarningMessages());
    }

    public function testValidateInvalidSignatureChain()
    {
        // Create chain where certificates exist but one doesn't sign the other
        // This would happen if we had certificates that aren't properly linked
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $ca = $this->makeTestCert('ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['ca']);
        
        $chainWithMissingLink = new Chain([
            $signer, // Signer
            // Skip the CA that should sign the signer certificate
            $intermediate_ca, // Intermediate CA
            $root_ca, // Root CA
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chainWithMissingLink, $trustStore);
        $this->assertFalse(
            $result->isValid,
            'Unexpected valid: ' . json_encode($result->getWarningMessages())
        );

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid);
        $this->assertGreaterThan(0, count($result->errors));
        $this->assertCount(0, $result->validatedChain);

        $errorMessages = $result->getErrorMessages();
        $this->assertStringContainsString('No complete certification path found', $errorMessages[0]);
    }

    public function testValidateWithMultipleValidationErrors()
    {
        // Test comprehensive error collection
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $ca = $this->makeTestCert('ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['ca']);
        
        $invalidChain = new Chain([
            $signer,
            $intermediate_ca, // Skip middle cert
        ]);

        $wrongTrustStore = new TrustStore([]); // Empty trust store

        $result = Validator::validateChain($invalidChain, $wrongTrustStore);
        $this->assertFalse(
            $result->isValid,
            'Unexpected valid: ' . json_encode($result->getWarningMessages())
        );

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid);
        $this->assertCount(0, $result->validatedChain);
        
        // Should have error about no complete path
        $errorMessages = $result->getErrorMessages();
        $this->assertGreaterThan(0, count($errorMessages));
        
        // Find the path building error
        $pathBuildingError = array_filter($errorMessages, fn($msg) => str_contains($msg, 'No complete certification path found'));
        $this->assertCount(1, $pathBuildingError);
    }

    public function testValidateErrorMessageFormatting()
    {
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        
        $emptyChain = new Chain([]);
        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($emptyChain, $trustStore);

        // Test error message formatting
        $this->assertCount(1, $result->errors);
        $error = $result->errors[0];
        $this->assertInstanceOf(ValidationError::class, $error);
        $this->assertEquals('No certificates in chain to validate', $error->message);
        $this->assertNull($error->certificate);
        $this->assertNull($error->context);

        // Test formatted message
        $this->assertEquals('No certificates in chain to validate', $error->getMessage());
    }

    public function testValidateMultiplePaths()
    {
        // Test scenario that could generate multiple paths (though unlikely with current test data)
        // This test verifies the warning system works correctly
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $ca = $this->makeTestCert('ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['ca']);
        
        $chain = new Chain([
            $signer,
            $ca,
            $intermediate_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        if (!$result->isValid) {
            $this->fail('Unexpected invalid: ' . implode(' | ', $result->getErrorMessages()));
        }

        // With current test data, this should succeed with no warnings
        // But the code is structured to handle multiple paths if they exist
        $this->assertTrue($result->isValid);
        $this->assertCount(0, $result->warnings); // Current test data produces single path
    }

    public function testThatIntermediateCaCantSignNonCaCertificates()
    {
        // Valid Case
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);

        $chain = new Chain([
            $signer,
            $intermediate_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertTrue(
            $result->isValid,
            'Unexpected invalid: ' . implode(' | ', $result->getErrorMessages())
        );

        // Invalid Case
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);

        $chain = new Chain([
            $signer,
            $intermediate_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertFalse(
            $result->isValid,
            'Unexpected valid: ' . json_encode($result->getWarningMessages())
        );
    }

    public function testThatRootCaWithoutIntermediateCaCantSignCaCertificates()
    {
        // Valid Case
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);

        $chain = new Chain([
            $signer,
            $intermediate_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertTrue(
            $result->isValid,
            'Unexpected invalid: ' . implode(' | ', $result->getErrorMessages())
        );

        // Invalid Case
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['intermediate_ca']);

        $chain = new Chain([
            $signer,
            $intermediate_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertFalse(
            $result->isValid,
            'Unexpected valid: ' . json_encode($result->getWarningMessages())
        );
    }

    public function testThatRootCaCantSignNonCaCertificates()
    {
        // Valid Case
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);

        $chain = new Chain([
            $signer,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertTrue(
            $result->isValid,
            'Unexpected invalid: ' . implode(' | ', $result->getErrorMessages())
        );

        // Invalid Case
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $signer = $this->makeTestCert('signer', [CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);

        $chain = new Chain([
            $signer,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertFalse(
            $result->isValid,
            'Unexpected valid: ' . json_encode($result->getWarningMessages())
        );
    }

    public function testValidateChainAddsMultiplePathsWarning()
    {
        // Root that can sign both CA-level and non-CA (INTERMEDIATE_CA | CA)
        $root = $this->makeTestCert('root', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root']);
        // Two parallel intermediates
        $i1 = $this->makeTestCert('i1', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root']);
        $i2 = $this->makeTestCert('i2', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root']);
        // Leaf signed by both intermediates
        $leaf = $this->makeTestCert('leaf', [CertificateFlag::DOCUMENT_SIGNER], ['i1', 'i2']);

        $chain = new Chain([$leaf, $i1, $i2, $root]);
        $store = new TrustStore([$root]);

        $result = Validator::validateChain($chain, $store);
        $this->assertTrue($result->isValid);
        $this->assertGreaterThanOrEqual(1, count($result->warnings));
        $this->assertTrue(array_any($result->getWarningMessages(), fn($m) => str_contains($m, 'Multiple certification paths found')));
    }

    public function testValidatePathEmptyArray()
    {
        $store = new TrustStore([]);
        $res = $this->invokeValidatePath([], $store);
        $this->assertFalse($res['isValid']);
        $this->assertTrue(array_any(array_map(fn($e) => $e->message, $res['errors']), fn($m) => $m === 'Empty certification path provided'));
    }

    public function testValidatePathNotEndingWithRoot()
    {
        // Create a CA signer that is not a root
        $ca = $this->makeTestCert('ca_only', [CertificateFlag::CA], ['ca_only']);
        // Leaf signed by this CA
        $leaf = $this->makeTestCert('leaf2', [CertificateFlag::DOCUMENT_SIGNER], ['ca_only']);

        $store = new TrustStore([]);
        $res = $this->invokeValidatePath([$leaf, $ca], $store);
        $this->assertFalse($res['isValid']);
        $this->assertTrue(array_any(array_map(fn($e) => $e->message, $res['errors']), fn($m) => str_contains($m, 'Path does not end with a root CA certificate')));
    }

    public function testValidatePathMissingSignatureBetweenAdjacentCerts()
    {
        // Use root as signer but omit root's signature on the leaf
        $root = $this->makeTestCert('root_abs', [CertificateFlag::ROOT_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_abs']);
        $leaf = $this->makeTestCert('leaf3', [CertificateFlag::DOCUMENT_SIGNER], []);

        // Path pairs leaf -> root (no signature by root)
        $store = new TrustStore([$root]);
        $res = $this->invokeValidatePath([$leaf, $root], $store);
        $this->assertFalse($res['isValid']);
        $this->assertTrue(array_any(array_map(fn($e) => $e->message, $res['errors']), fn($m) => str_contains($m, 'Certificate is not signed by the next certificate in path')));
    }

    public function testValidatePathInvalidSignatureBetweenAdjacentCerts()
    {
        // Build signer and leaf with forged signature bytes
        $signer = $this->makeTestCert('bad_signer', [CertificateFlag::ROOT_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['bad_signer']);

        // Create a leaf with an invalid signature referencing signer's KeyId
        $kp = $this->certificates['bad_signer']['key'];
        $leaf_base = new Certificate(
            key: Ed25519::makeKeyPair()->toPublicKey(),
            description: 'leaf_bad_sig',
            userDescriptors: [new UserDescriptor(DescriptorType::USERNAME, 'leaf_bad')],
            flags: CertificateFlagsCollection::fromList([CertificateFlag::DOCUMENT_SIGNER]),
            signatures: []
        );
        $forged = new Signature($kp->id, BinaryString::fromHex(str_repeat('00', 64)));
        $leaf = $leaf_base->with(signatures: [$forged]);

        $store = new TrustStore([$signer]);
        $res = $this->invokeValidatePath([$leaf, $signer], $store);
        $this->assertFalse($res['isValid']);
        $this->assertTrue(array_any(array_map(fn($e) => $e->message, $res['errors']), fn($m) => str_contains($m, 'Invalid signature on certificate')));
    }

    public function testRootSelfSignatureInvalid()
    {
        // Create a valid chain leaf -> intermediate -> root, then corrupt the root's self-signature
        $rootKey = Ed25519::makeKeyPair();
        $rootBase = new Certificate(
            key: $rootKey->toPublicKey(),
            description: 'root_invalid_self',
            userDescriptors: [new UserDescriptor(DescriptorType::USERNAME, 'root')],
            flags: CertificateFlagsCollection::fromList([CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER]),
            signatures: []
        );
        // Add an invalid (but present) self-signature using the correct KeyId
        $invalidSelf = new Signature($rootKey->id, BinaryString::fromHex(str_repeat('00', 64)));
        $root = $rootBase->with(signatures: [$invalidSelf]);

        $interKey = Ed25519::makeKeyPair();
        $interBase = new Certificate(
            key: $interKey->toPublicKey(),
            description: 'inter',
            userDescriptors: [new UserDescriptor(DescriptorType::USERNAME, 'inter')],
            flags: CertificateFlagsCollection::fromList([CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER]),
            signatures: []
        );
        $inter = $interBase->with(signatures: [Signature::make($interBase->toBinaryForSigning(), $rootKey)]);

        $leafKey = Ed25519::makeKeyPair();
        $leafBase = new Certificate(
            key: $leafKey->toPublicKey(),
            description: 'leaf',
            userDescriptors: [new UserDescriptor(DescriptorType::USERNAME, 'leaf')],
            flags: CertificateFlagsCollection::fromList([CertificateFlag::DOCUMENT_SIGNER]),
            signatures: []
        );
        $leaf = $leafBase->with(signatures: [Signature::make($leafBase->toBinaryForSigning(), $interKey)]);

        $chain = new Chain([$leaf, $inter, $root]);
        $store = new TrustStore([$root]);

        $result = Validator::validateChain($chain, $store);
        $this->assertFalse($result->isValid);
        $this->assertTrue(array_any($result->getErrorMessages(), fn($m) => str_contains($m, 'Invalid self-signature on root CA certificate')));
    }

    // Note: Catch branches that rely on exceptions during signature verification are
    // intentionally not tested here because Signature::validate() only throws when
    // the KeyId does not match the provided key, which cannot occur for a true
    // self-signature selected via getSelfSignature().

    public function testCaCertificateMustBeSignedByIntermediateCa()
    {
        // Build: target CA signed by a signer that has only CA (not INTERMEDIATE_CA) -> invalid
        $root_ca = $this->makeTestCert('root_for_ca_target', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA], ['root_for_ca_target']);
        $ca_signer_only_ca = $this->makeTestCert('ca_signer_only_ca', [CertificateFlag::CA], ['root_for_ca_target']);
        $ca_target = $this->makeTestCert('ca_target', [CertificateFlag::CA], ['ca_signer_only_ca']);

        $chain = new Chain([
            $ca_target,
            $ca_signer_only_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertFalse($result->isValid);
        $messages = $result->getErrorMessages();
        $this->assertTrue(array_any($messages, fn($m) => str_contains($m, 'Certificate with CA flags must be signed by a certificate with INTERMEDIATE_CA flag')));
    }

    public function testIntermediateCaCannotSignNonCaCertificate()
    {
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA], ['root_ca']);
        $intermediate_only = $this->makeTestCert('intermediate_only', [CertificateFlag::INTERMEDIATE_CA], ['root_ca']);
        $leaf = $this->makeTestCert('leaf', [CertificateFlag::DOCUMENT_SIGNER], ['intermediate_only']);

        $chain = new Chain([
            $leaf,
            $intermediate_only,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertFalse($result->isValid);
        $messages = $result->getErrorMessages();
        $this->assertTrue(array_any($messages, fn($m) => str_contains($m, 'Non-CA certificate must be signed by a certificate with CA flag')));
    }

    public function testIntermediateCaCanSignCaCertificateWithoutCaFlag()
    {
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA], ['root_ca']);
        $intermediate_only = $this->makeTestCert('intermediate_only', [CertificateFlag::INTERMEDIATE_CA], ['root_ca']);
        $ca_target = $this->makeTestCert('ca_target', [CertificateFlag::CA], ['intermediate_only']);

        $chain = new Chain([
            $ca_target,
            $intermediate_only,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertTrue($result->isValid);
    }

    public function testCertificateWithRootCaFlagMustBeSelfSigned()
    {
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA], ['root_ca']);
        $fake_root = $this->makeTestCert('fake_root', [CertificateFlag::ROOT_CA, CertificateFlag::CA], ['root_ca']);

        $chain = new Chain([
            $fake_root,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertFalse($result->isValid);
        $messages = $result->getErrorMessages();
        $this->assertTrue(array_any($messages, fn($m) => str_contains($m, 'Certificate with ROOT_CA flag must be self-signed')));
    }

    public function testEndEntityFlagsMustBeSubsetOfSigner()
    {
        // Build: subject with DOCUMENT_SIGNER signed by signer with only CA (no end-entity flags) -> invalid
        $root_ca = $this->makeTestCert('root_for_subset', [CertificateFlag::ROOT_CA, CertificateFlag::CA], ['root_for_subset']);
        $signer_only_ca = $this->makeTestCert('signer_only_ca', [CertificateFlag::CA], ['root_for_subset']);
        $subject_with_doc = $this->makeTestCert('subject_with_doc', [CertificateFlag::DOCUMENT_SIGNER], ['signer_only_ca']);

        $chain = new Chain([
            $subject_with_doc,
            $signer_only_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertFalse($result->isValid);
        $messages = $result->getErrorMessages();
        $this->assertTrue(array_any($messages, fn($m) => str_contains($m, 'Certificate end-entity flags must be a subset of signer')));


        // Build: subject with DOCUMENT_SIGNER signed by signer with only CA (no end-entity flags) -> invalid
        $root_ca = $this->makeTestCert('root_for_subset', [CertificateFlag::ROOT_CA, CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER], ['root_for_subset']);
        $signer_only_ca = $this->makeTestCert('signer_only_ca', [CertificateFlag::CA], ['root_for_subset']);
        $subject_with_doc = $this->makeTestCert('subject_with_doc', [CertificateFlag::DOCUMENT_SIGNER], ['signer_only_ca']);

        $chain = new Chain([
            $subject_with_doc,
            $signer_only_ca,
            $root_ca,
        ]);

        $trustStore = new TrustStore([
            $root_ca,
        ]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertFalse($result->isValid);
        $messages = $result->getErrorMessages();
        $this->assertTrue(array_any($messages, fn($m) => str_contains($m, 'Certificate end-entity flags must be a subset of signer')));
    }

    public function testRootSelfSignedAllowsAnyEndEntityFlagsForSameKey()
    {
        // Hit the early return in validateEndEntityFlagInheritance when signer is self-signed ROOT_CA
        $rootKey = Ed25519::makeKeyPair();

        // Root certificate: ROOT_CA + CA, self-signed
        $rootCertBase = new Certificate(
            key: $rootKey->toPublicKey(),
            description: 'root_self',
            userDescriptors: [new UserDescriptor(DescriptorType::USERNAME, 'root')],
            flags: CertificateFlagsCollection::fromList([CertificateFlag::ROOT_CA, CertificateFlag::CA]),
            signatures: []
        );
        $rootSelfSig = Signature::make($rootCertBase->toBinaryForSigning(), $rootKey);
        $rootCert = $rootCertBase->with(signatures: [$rootSelfSig]);

        // Child certificate that uses the SAME key id/public key as root, with an end-entity flag
        $childBase = new Certificate(
            key: $rootKey->toPublicKey(),
            description: 'child_same_key',
            userDescriptors: [new UserDescriptor(DescriptorType::USERNAME, 'child')],
            flags: CertificateFlagsCollection::fromList([CertificateFlag::DOCUMENT_SIGNER]),
            signatures: []
        );
        $childSigByRoot = Signature::make($childBase->toBinaryForSigning(), $rootKey);
        $childCert = $childBase->with(signatures: [$childSigByRoot]);

        $chain = new Chain([
            $childCert,
            $rootCert,
        ]);

        $trustStore = new TrustStore([$rootCert]);

        $result = Validator::validateChain($chain, $trustStore);
        $this->assertTrue($result->isValid);
    }
}
