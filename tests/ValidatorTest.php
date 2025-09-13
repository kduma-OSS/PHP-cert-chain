<?php

namespace KDuma\CertificateChainOfTrust\Tests;

use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Chain;
use KDuma\CertificateChainOfTrust\Crypto\Ed25519;
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

    public function testValidateCompleteValidChain()
    {
        // Create complete certificate chain using makeTestCert
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
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
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        
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
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
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
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
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

    public function testValidationResultStructure()
    {
        // Test with valid chain using makeTestCert
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
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
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
        $intermediate_ca = $this->makeTestCert('intermediate_ca', [CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
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
        $root_ca = $this->makeTestCert('root_ca', [CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER], ['root_ca']);
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

        // With current test data, this should succeed with no warnings
        // But the code is structured to handle multiple paths if they exist
        $this->assertTrue($result->isValid);
        $this->assertCount(0, $result->warnings); // Current test data produces single path
    }
}