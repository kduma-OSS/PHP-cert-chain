<?php

namespace KDuma\CertificateChainOfTrust\Tests;

use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Chain;
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
    const array EXAMPLE_CERTS = [
        'CERTAcvqzcCWF+Plt90g93ZAGV6WOt6GDZe80h4KaD5cocEA2E/oMEJQomXDGR14OzSljRpFeGFtcGxlIFNpZ25lciBDZXJ0aWZpY2F0ZQEDABJzaWduZXIuZXhhbXBsZS5jb20DAAEeAgBwvi0pC50NSVuou6TUc8wOL6hEIBn4DdZJtnRTG00H1B0UJZRKAWWo2YOYYW/f4gJsBaQ3NGC2G45xXg5B++gpEhowfZNY8EFV1zqLBQ==',
        'CERTAR4CAHC+LSkLnQ1JW6i7pNTOJOAFvUe856zNgY4Dm0uxCPKHR0zDc58vziPsAU7JghZFeGFtcGxlIENBIENlcnRpZmljYXRlAQMADmNhLmV4YW1wbGUuY29tAwQB41bjk0DLeETOIgPuW8Kx9ow9xhT+ylstRfvIktC9EO28uT/Z4lTAa+H52d1t7qZ5Qc5GXD6Q6l5rS9ASgQgZTgDsyfBlKUUFxzC9tvUADww=',
        'CERTAeNW45NAy3hEziID7lvCsfZ3EMHnQFCvqUxr07jGQXyl8wQ83TpNGnOCEGxOUYg1CCNFeGFtcGxlIEludGVybWVkaWF0ZSBDQSBDZXJ0aWZpY2F0ZQEDABhpbnRlcm1lZGlhdGUuZXhhbXBsZS5jb20DBgFY0TIpXLtX/tk79S+G+oCdPB8ECk4b15eCMYPFAuBxipqF2Nwjj847RvLaw08DPHu7/7Uh7U1QdfntbO5sJLbw2bXx6d5PaaGKpGOnqOrGBQ==',
        'CERTAVjRMilcu1f+2Tv1L4b6gJ3HVeE/YCex4hSFvT1RjNnhtRZovhI8NjSj2rUiiOiTCxtFeGFtcGxlIFJvb3QgQ0EgQ2VydGlmaWNhdGUBAwAQcm9vdC5leGFtcGxlLmNvbQMHAVjRMilcu1f+2Tv1L4b6gJ0eZuMAzrTmI10gs8GZjruuy5tlczYYcRnV9UN4r+fCo05FEqmui2/WJVVBi2Nj+H3DaMrlRC62so24CSta31AH',
    ];

    public function testValidateCompleteValidChain()
    {
        // Create complete certificate chain
        $chain = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])), // Signer
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])), // CA
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[2])), // Intermediate CA
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])), // Root CA
        ]);

        // Create trust store with root CA
        $trustStore = new TrustStore([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])), // Root CA
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
        $this->assertEquals('cbeacdc09617e3e5b7dd20f77640195e', $result->validatedChain[0]->key->id->toHex());
        $this->assertEquals('1e020070be2d290b9d0d495ba8bba4d4', $result->validatedChain[1]->key->id->toHex());
        $this->assertEquals('e356e39340cb7844ce2203ee5bc2b1f6', $result->validatedChain[2]->key->id->toHex());
        $this->assertEquals('58d132295cbb57fed93bf52f86fa809d', $result->validatedChain[3]->key->id->toHex());
    }

    public function testValidateEmptyChain()
    {
        $emptyChain = new Chain([]);
        $trustStore = new TrustStore([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
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
        // Create incomplete chain (missing intermediate and root CA)
        $incompleteChain = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])), // Signer
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])), // CA
            // Missing intermediate CA and root CA
        ]);

        $trustStore = new TrustStore([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])), // Root CA
        ]);

        $result = Validator::validateChain($incompleteChain, $trustStore);

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid);
        $this->assertCount(1, $result->errors);
        $this->assertCount(0, $result->warnings);
        $this->assertCount(0, $result->validatedChain);

        $errorMessages = $result->getErrorMessages();
        $this->assertStringContainsString('No complete certification path found', $errorMessages[0]);
        $this->assertStringContainsString('Certificate: cbeacdc09617e3e5b7dd20f77640195e', $errorMessages[0]);
        $this->assertStringContainsString('[path building]', $errorMessages[0]);
    }

    public function testValidateRootNotInTrustStore()
    {
        // Create complete valid chain
        $chain = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[2])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
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
        $this->assertStringContainsString('Certificate: 58d132295cbb57fed93bf52f86fa809d', $errorMessages[1]);
        $this->assertStringContainsString('[trust store validation]', $errorMessages[1]);
    }

    public function testValidationResultStructure()
    {
        // Test with valid chain
        $validChain = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[2])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
        ]);

        $trustStore = new TrustStore([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
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
        $chainWithMissingLink = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])), // Signer
            // Skip the CA that should sign the signer certificate
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[2])), // Intermediate CA
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])), // Root CA
        ]);

        $trustStore = new TrustStore([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
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
        $invalidChain = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[2])), // Skip middle cert
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
        $emptyChain = new Chain([]);
        $trustStore = new TrustStore([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
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
        $chain = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[2])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
        ]);

        $trustStore = new TrustStore([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
        ]);

        $result = Validator::validateChain($chain, $trustStore);

        // With current test data, this should succeed with no warnings
        // But the code is structured to handle multiple paths if they exist
        $this->assertTrue($result->isValid);
        $this->assertCount(0, $result->warnings); // Current test data produces single path
    }
}