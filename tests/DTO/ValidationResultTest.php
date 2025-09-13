<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\Tests\DTO;

use KDuma\BinaryTools\BinaryString;
use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\DTO\ValidationElement;
use KDuma\CertificateChainOfTrust\DTO\ValidationError;
use KDuma\CertificateChainOfTrust\DTO\ValidationResult;
use KDuma\CertificateChainOfTrust\DTO\ValidationWarning;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ValidationResult::class)]
#[CoversClass(ValidationElement::class)]
#[CoversClass(ValidationWarning::class)]
#[CoversClass(ValidationError::class)]
class ValidationResultTest extends TestCase
{
    public const string EXAMPLE_CERT = 'CERTAeNW45NAy3hEziID7lvCsfZ3EMHnQFCvqUxr07jGQXyl8wQ83TpNGnOCEGxOUYg1CCNFeGFtcGxlIEludGVybWVkaWF0ZSBDQSBDZXJ0aWZpY2F0ZQEDABhpbnRlcm1lZGlhdGUuZXhhbXBsZS5jb20DBgFY0TIpXLtX/tk79S+G+oCdPB8ECk4b15eCMYPFAuBxipqF2Nwjj847RvLaw08DPHu7/7Uh7U1QdfntbO5sJLbw2bXx6d5PaaGKpGOnqOrGBQ==';
    public const string EXAMPLE_ROOT_CERT = 'CERTAVjRMilcu1f+2Tv1L4b6gJ3HVeE/YCex4hSFvT1RjNnhtRZovhI8NjSj2rUiiOiTCxtFeGFtcGxlIFJvb3QgQ0EgQ2VydGlmaWNhdGUBAwAQcm9vdC5leGFtcGxlLmNvbQMHAVjRMilcu1f+2Tv1L4b6gJ0eZuMAzrTmI10gs8GZjruuy5tlczYYcRnV9UN4r+fCo05FEqmui2/WJVVBi2Nj+H3DaMrlRC62so24CSta31AH';

    public function testValidationErrorConstruct()
    {
        // Test basic constructor
        $error = new ValidationError('Test error message');
        $this->assertEquals('Test error message', $error->message);
        $this->assertNull($error->certificate);
        $this->assertNull($error->context);

        // Test with certificate
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $error = new ValidationError('Certificate error', $cert);
        $this->assertEquals('Certificate error', $error->message);
        $this->assertEquals($cert, $error->certificate);
        $this->assertNull($error->context);

        // Test with context
        $error = new ValidationError('Context error', null, 'test context');
        $this->assertEquals('Context error', $error->message);
        $this->assertNull($error->certificate);
        $this->assertEquals('test context', $error->context);

        // Test with all parameters
        $error = new ValidationError('Full error', $cert, 'full context');
        $this->assertEquals('Full error', $error->message);
        $this->assertEquals($cert, $error->certificate);
        $this->assertEquals('full context', $error->context);
    }

    public function testValidationWarningConstruct()
    {
        // Test basic constructor
        $warning = new ValidationWarning('Test warning message');
        $this->assertEquals('Test warning message', $warning->message);
        $this->assertNull($warning->certificate);
        $this->assertNull($warning->context);

        // Test with certificate
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $warning = new ValidationWarning('Certificate warning', $cert);
        $this->assertEquals('Certificate warning', $warning->message);
        $this->assertEquals($cert, $warning->certificate);
        $this->assertNull($warning->context);

        // Test with context
        $warning = new ValidationWarning('Context warning', null, 'test context');
        $this->assertEquals('Context warning', $warning->message);
        $this->assertNull($warning->certificate);
        $this->assertEquals('test context', $warning->context);

        // Test with all parameters
        $warning = new ValidationWarning('Full warning', $cert, 'full context');
        $this->assertEquals('Full warning', $warning->message);
        $this->assertEquals($cert, $warning->certificate);
        $this->assertEquals('full context', $warning->context);
    }

    public function testValidationElementGetMessage()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));

        // Test basic message only
        $error = new ValidationError('Basic message');
        $this->assertEquals('Basic message', $error->getMessage());

        // Test message with certificate
        $error = new ValidationError('Certificate message', $cert);
        $expectedMessage = 'Certificate message (Certificate: e356e39340cb7844ce2203ee5bc2b1f6)';
        $this->assertEquals($expectedMessage, $error->getMessage());

        // Test message with context
        $error = new ValidationError('Context message', null, 'validation context');
        $this->assertEquals('Context message [validation context]', $error->getMessage());

        // Test message with both certificate and context
        $error = new ValidationError('Full message', $cert, 'full context');
        $expectedMessage = 'Full message (Certificate: e356e39340cb7844ce2203ee5bc2b1f6) [full context]';
        $this->assertEquals($expectedMessage, $error->getMessage());

        // Test with ValidationWarning as well
        $warning = new ValidationWarning('Warning with cert', $cert, 'warning context');
        $expectedMessage = 'Warning with cert (Certificate: e356e39340cb7844ce2203ee5bc2b1f6) [warning context]';
        $this->assertEquals($expectedMessage, $warning->getMessage());
    }

    public function testValidationResultConstruct()
    {
        // Test default constructor
        $result = new ValidationResult();
        $this->assertEquals([], $result->errors);
        $this->assertEquals([], $result->warnings);
        $this->assertEquals([], $result->validatedChain);
        $this->assertTrue($result->isValid);

        // Test with parameters
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $rootCert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_ROOT_CERT));

        $errors = [
            new ValidationError('Error 1'),
            new ValidationError('Error 2', $cert)
        ];
        $warnings = [
            new ValidationWarning('Warning 1'),
            new ValidationWarning('Warning 2', $rootCert, 'context')
        ];
        $validatedChain = [$cert, $rootCert];

        $result = new ValidationResult($errors, $warnings, $validatedChain, false);
        $this->assertEquals($errors, $result->errors);
        $this->assertEquals($warnings, $result->warnings);
        $this->assertEquals($validatedChain, $result->validatedChain);
        $this->assertFalse($result->isValid);
    }

    public function testValidationResultGetErrorMessages()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));

        // Test with empty errors
        $result = new ValidationResult();
        $this->assertEquals([], $result->getErrorMessages());

        // Test with multiple errors
        $errors = [
            new ValidationError('First error'),
            new ValidationError('Second error', $cert),
            new ValidationError('Third error', null, 'context'),
            new ValidationError('Fourth error', $cert, 'full context')
        ];

        $result = new ValidationResult($errors);
        $messages = $result->getErrorMessages();

        $this->assertCount(4, $messages);
        $this->assertEquals('First error', $messages[0]);
        $this->assertEquals('Second error (Certificate: e356e39340cb7844ce2203ee5bc2b1f6)', $messages[1]);
        $this->assertEquals('Third error [context]', $messages[2]);
        $this->assertEquals('Fourth error (Certificate: e356e39340cb7844ce2203ee5bc2b1f6) [full context]', $messages[3]);
    }

    public function testValidationResultGetWarningMessages()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_ROOT_CERT));

        // Test with empty warnings
        $result = new ValidationResult();
        $this->assertEquals([], $result->getWarningMessages());

        // Test with multiple warnings
        $warnings = [
            new ValidationWarning('First warning'),
            new ValidationWarning('Second warning', $cert),
            new ValidationWarning('Third warning', null, 'warning context'),
            new ValidationWarning('Fourth warning', $cert, 'full warning context')
        ];

        $result = new ValidationResult([], $warnings);
        $messages = $result->getWarningMessages();

        $this->assertCount(4, $messages);
        $this->assertEquals('First warning', $messages[0]);
        $this->assertEquals('Second warning (Certificate: 58d132295cbb57fed93bf52f86fa809d)', $messages[1]);
        $this->assertEquals('Third warning [warning context]', $messages[2]);
        $this->assertEquals('Fourth warning (Certificate: 58d132295cbb57fed93bf52f86fa809d) [full warning context]', $messages[3]);
    }

    public function testValidationResultComplexScenario()
    {
        $cert1 = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $cert2 = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_ROOT_CERT));

        $errors = [
            new ValidationError('Signature verification failed', $cert1, 'chain validation'),
            new ValidationError('Certificate expired', $cert2)
        ];

        $warnings = [
            new ValidationWarning('Certificate near expiry', $cert1),
            new ValidationWarning('Weak signature algorithm', $cert2, 'security check')
        ];

        $validatedChain = [$cert1, $cert2];

        $result = new ValidationResult($errors, $warnings, $validatedChain, false);

        // Test that all data is preserved
        $this->assertCount(2, $result->errors);
        $this->assertCount(2, $result->warnings);
        $this->assertCount(2, $result->validatedChain);
        $this->assertFalse($result->isValid);

        // Test message extraction
        $errorMessages = $result->getErrorMessages();
        $this->assertCount(2, $errorMessages);
        $this->assertEquals('Signature verification failed (Certificate: e356e39340cb7844ce2203ee5bc2b1f6) [chain validation]', $errorMessages[0]);
        $this->assertEquals('Certificate expired (Certificate: 58d132295cbb57fed93bf52f86fa809d)', $errorMessages[1]);

        $warningMessages = $result->getWarningMessages();
        $this->assertCount(2, $warningMessages);
        $this->assertEquals('Certificate near expiry (Certificate: e356e39340cb7844ce2203ee5bc2b1f6)', $warningMessages[0]);
        $this->assertEquals('Weak signature algorithm (Certificate: 58d132295cbb57fed93bf52f86fa809d) [security check]', $warningMessages[1]);
    }

    public function testInheritanceAndPolymorphism()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));

        // Test that both ValidationError and ValidationWarning are instances of ValidationElement
        $error = new ValidationError('Test error', $cert, 'error context');
        $warning = new ValidationWarning('Test warning', $cert, 'warning context');

        $this->assertInstanceOf(ValidationElement::class, $error);
        $this->assertInstanceOf(ValidationElement::class, $warning);

        // Test polymorphic behavior
        $elements = [$error, $warning];
        foreach ($elements as $element) {
            $this->assertInstanceOf(ValidationElement::class, $element);
            $message = $element->getMessage();
            $this->assertStringContainsString('(Certificate: e356e39340cb7844ce2203ee5bc2b1f6)', $message);
            $this->assertStringContainsString('context]', $message);
        }
    }
}
