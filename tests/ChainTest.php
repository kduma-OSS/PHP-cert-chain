<?php

namespace KDuma\CertificateChainOfTrust\Tests;

use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Chain;
use KDuma\CertificateChainOfTrust\Crypto\KeyId;
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

    public function testGetCertificate()
    {
        $chain = Chain::fromBinary(BinaryString::fromBase64(self::EXAMPLE_1));
        $this->assertCount(4, $chain->certificates);

        $certificate = $chain->getFirstCertificate();
        $this->assertInstanceOf(Certificate::class, $certificate);
        $this->assertEquals(self::EXAMPLE_CERTS[0], $certificate->toBinary()->toBase64());

        $emptyChain = new Chain([]);
        $this->assertNull($emptyChain->getFirstCertificate());
    }


    public function testBuildPaths()
    {
        $chain = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[2])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])),
        ]);

        $paths = $chain->buildPaths($chain->certificates[1]);
        $this->assertCount(1, $paths);
        $this->assertCount(3, $paths[0]);

        $this->assertEquals('1e020070be2d290b9d0d495ba8bba4d4', $paths[0][0]->key->id->toHex());
        $this->assertEquals('e356e39340cb7844ce2203ee5bc2b1f6', $paths[0][1]->key->id->toHex());
        $this->assertEquals('58d132295cbb57fed93bf52f86fa809d', $paths[0][2]->key->id->toHex());

        $paths = $chain->buildPaths();
        $this->assertCount(1, $paths);
        $this->assertCount(4, $paths[0]);

        $this->assertEquals('cbeacdc09617e3e5b7dd20f77640195e', $paths[0][0]->key->id->toHex());
        $this->assertEquals('1e020070be2d290b9d0d495ba8bba4d4', $paths[0][1]->key->id->toHex());
        $this->assertEquals('e356e39340cb7844ce2203ee5bc2b1f6', $paths[0][2]->key->id->toHex());
        $this->assertEquals('58d132295cbb57fed93bf52f86fa809d', $paths[0][3]->key->id->toHex());

        $chain = new Chain([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])),
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[2])),
            // Missing root CA
        ]);

        $paths = $chain->buildPaths();
        $this->assertCount(0, $paths);

        $chain = new Chain([]);

        $paths = $chain->buildPaths();
        $this->assertCount(0, $paths);
    }

    public function testGetRootCertificates()
    {
        $chain = Chain::fromBinary(BinaryString::fromBase64(self::EXAMPLE_1));
        $this->assertCount(4, $chain->certificates);

        $rootCertificates = $chain->getRootCertificates();
        $this->assertCount(1, $rootCertificates);
        $this->assertTrue($rootCertificates[0]->isRootCA());
        $this->assertEquals(self::EXAMPLE_CERTS[3], $rootCertificates[0]->toBinary()->toBase64());
    }

    public function testGetLeafCertificates()
    {
        $chain = Chain::fromBinary(BinaryString::fromBase64(self::EXAMPLE_1));
        $this->assertCount(4, $chain->certificates);

        $leafCertificates = $chain->getLeafCertificates();
        $this->assertCount(1, $leafCertificates);
        $this->assertFalse($leafCertificates[0]->isRootCA());
        $this->assertEquals(self::EXAMPLE_CERTS[0], $leafCertificates[0]->toBinary()->toBase64());
    }

    public function testGetById()
    {
        $chain = Chain::fromBinary(BinaryString::fromBase64(self::EXAMPLE_1));
        $this->assertEquals(Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[3])), $chain->getById(KeyId::fromHex('58d132295cbb57fed93bf52f86fa809d')));
        $this->assertNull($chain->getById(KeyId::fromString('nonexistent')));
    }



}
