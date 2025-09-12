<?php

namespace KDuma\CertificateChainOfTrust\Tests;

use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Chain;
use KDuma\CertificateChainOfTrust\Utils\BinaryReader;
use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Chain::class)]
class ChainTest extends TestCase
{
    const string EXAMPLE_1 = 'CERTAcvqzcCWF+Plt90g93ZAGV6WOt6GDZe80h4KaD5cocEA2E/oMEJQomXDGR14OzSljRpFeGFtcGxlIFNpZ25lciBDZXJ0aWZpY2F0ZQEDABJzaWduZXIuZXhhbXBsZS5jb20DAAEeAgBwvi0pC50NSVuou6TUc8wOL6hEIBn4DdZJtnRTG00H1B0UJZRKAWWo2YOYYW/f4gJsBaQ3NGC2G45xXg5B++gpEhowfZNY8EFV1zqLBQhEUwEeAgBwvi0pC50NSVuou6TUziTgBb1HvOeszYGOA5tLsQjyh0dMw3OfL84j7AFOyYIWRXhhbXBsZSBDQSBDZXJ0aWZpY2F0ZQEDAA5jYS5leGFtcGxlLmNvbQMEAeNW45NAy3hEziID7lvCsfaMPcYU/spbLUX7yJLQvRDtvLk/2eJUwGvh+dndbe6meUHORlw+kOpea0vQEoEIGU4A7MnwZSlFBccwvbb1AA8MCERTAeNW45NAy3hEziID7lvCsfZ3EMHnQFCvqUxr07jGQXyl8wQ83TpNGnOCEGxOUYg1CCNFeGFtcGxlIEludGVybWVkaWF0ZSBDQSBDZXJ0aWZpY2F0ZQEDABhpbnRlcm1lZGlhdGUuZXhhbXBsZS5jb20DBgFY0TIpXLtX/tk79S+G+oCdPB8ECk4b15eCMYPFAuBxipqF2Nwjj847RvLaw08DPHu7/7Uh7U1QdfntbO5sJLbw2bXx6d5PaaGKpGOnqOrGBQhEUwFY0TIpXLtX/tk79S+G+oCdx1XhP2AnseIUhb09UYzZ4bUWaL4SPDY0o9q1IojokwsbRXhhbXBsZSBSb290IENBIENlcnRpZmljYXRlAQMAEHJvb3QuZXhhbXBsZS5jb20DBwFY0TIpXLtX/tk79S+G+oCdHmbjAM605iNdILPBmY67rsubZXM2GHEZ1fVDeK/nwqNORRKprotv1iVVQYtjY/h9w2jK5UQutrKNuAkrWt9QBw==';

    const array EXAMPLE_CERTS = [
        'CERTAcvqzcCWF+Plt90g93ZAGV6WOt6GDZe80h4KaD5cocEA2E/oMEJQomXDGR14OzSljRpFeGFtcGxlIFNpZ25lciBDZXJ0aWZpY2F0ZQEDABJzaWduZXIuZXhhbXBsZS5jb20DAAEeAgBwvi0pC50NSVuou6TUc8wOL6hEIBn4DdZJtnRTG00H1B0UJZRKAWWo2YOYYW/f4gJsBaQ3NGC2G45xXg5B++gpEhowfZNY8EFV1zqLBQ==',
        'CERTAR4CAHC+LSkLnQ1JW6i7pNTOJOAFvUe856zNgY4Dm0uxCPKHR0zDc58vziPsAU7JghZFeGFtcGxlIENBIENlcnRpZmljYXRlAQMADmNhLmV4YW1wbGUuY29tAwQB41bjk0DLeETOIgPuW8Kx9ow9xhT+ylstRfvIktC9EO28uT/Z4lTAa+H52d1t7qZ5Qc5GXD6Q6l5rS9ASgQgZTgDsyfBlKUUFxzC9tvUADww=',
        'CERTAeNW45NAy3hEziID7lvCsfZ3EMHnQFCvqUxr07jGQXyl8wQ83TpNGnOCEGxOUYg1CCNFeGFtcGxlIEludGVybWVkaWF0ZSBDQSBDZXJ0aWZpY2F0ZQEDABhpbnRlcm1lZGlhdGUuZXhhbXBsZS5jb20DBgFY0TIpXLtX/tk79S+G+oCdPB8ECk4b15eCMYPFAuBxipqF2Nwjj847RvLaw08DPHu7/7Uh7U1QdfntbO5sJLbw2bXx6d5PaaGKpGOnqOrGBQ==',
        'CERTAVjRMilcu1f+2Tv1L4b6gJ3HVeE/YCex4hSFvT1RjNnhtRZovhI8NjSj2rUiiOiTCxtFeGFtcGxlIFJvb3QgQ0EgQ2VydGlmaWNhdGUBAwAQcm9vdC5leGFtcGxlLmNvbQMHAVjRMilcu1f+2Tv1L4b6gJ0eZuMAzrTmI10gs8GZjruuy5tlczYYcRnV9UN4r+fCo05FEqmui2/WJVVBi2Nj+H3DaMrlRC62so24CSta31AH',
    ];
    public function test__construct()
    {
        $chain = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[2])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
        ]);

        $this->assertCount(4, $chain->certificates);
        $this->assertInstanceOf(Certificate::class, $chain->certificates[0]);
        $this->assertEquals('Example Signer Certificate', $chain->certificates[0]->description);

        try {
            $chain = new Chain([
                Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])),
                new \stdClass(), // Invalid element
            ]);
            $this->fail('Expected InvalidArgumentException not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('All elements of $certificates must be instances of Certificate', $e->getMessage());
        }
    }

    public function testToBinary()
    {
        $chain = Chain::fromBinary(BinaryString::fromBase64(self::EXAMPLE_1));

        $this->assertEquals(self::EXAMPLE_1, $chain->toBinary()->toBase64());
    }

    public function testFromBinary()
    {
        $chain = Chain::fromBinary(BinaryString::fromBase64(self::EXAMPLE_1));

        $this->assertCount(4, $chain->certificates);
    }

    public function testFromBinaryReader()
    {
        $reader = new BinaryReader(BinaryString::fromBase64(self::EXAMPLE_1));
        $chain = Chain::fromBinaryReader($reader);

        $this->assertCount(4, $chain->certificates);
        $this->assertEquals($reader->length, $reader->position);
    }
}
