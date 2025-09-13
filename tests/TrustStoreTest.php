<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\Tests;

use KDuma\BinaryTools\BinaryString;
use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\TrustStore;
use PHPUnit\Framework\TestCase;

class TrustStoreTest extends TestCase
{
    public const string EXAMPLE_1 = 'TrustedKCERTAVjRMilcu1f+2Tv1L4b6gJ3HVeE/YCex4hSFvT1RjNnhtRZovhI8NjSj2rUiiOiTCxtFeGFtcGxlIFJvb3QgQ0EgQ2VydGlmaWNhdGUBAwAQcm9vdC5leGFtcGxlLmNvbQMHAVjRMilcu1f+2Tv1L4b6gJ0eZuMAzrTmI10gs8GZjruuy5tlczYYcRnV9UN4r+fCo05FEqmui2/WJVVBi2Nj+H3DaMrlRC62so24CSta31AH';

    public const array EXAMPLE_CERTS = [
        'CERTAeNW45NAy3hEziID7lvCsfZ3EMHnQFCvqUxr07jGQXyl8wQ83TpNGnOCEGxOUYg1CCNFeGFtcGxlIEludGVybWVkaWF0ZSBDQSBDZXJ0aWZpY2F0ZQEDABhpbnRlcm1lZGlhdGUuZXhhbXBsZS5jb20DBgFY0TIpXLtX/tk79S+G+oCdPB8ECk4b15eCMYPFAuBxipqF2Nwjj847RvLaw08DPHu7/7Uh7U1QdfntbO5sJLbw2bXx6d5PaaGKpGOnqOrGBQ==',
        'CERTAVjRMilcu1f+2Tv1L4b6gJ3HVeE/YCex4hSFvT1RjNnhtRZovhI8NjSj2rUiiOiTCxtFeGFtcGxlIFJvb3QgQ0EgQ2VydGlmaWNhdGUBAwAQcm9vdC5leGFtcGxlLmNvbQMHAVjRMilcu1f+2Tv1L4b6gJ0eZuMAzrTmI10gs8GZjruuy5tlczYYcRnV9UN4r+fCo05FEqmui2/WJVVBi2Nj+H3DaMrlRC62so24CSta31AH',
    ];

    public function testFromBinary()
    {
        $store = TrustStore::fromBinary(BinaryString::fromBase64(self::EXAMPLE_1));

        $this->assertCount(1, $store->certificates);
        $this->assertEquals('Example Root CA Certificate', $store->certificates[0]->description);
    }

    public function testFromBinaryInvalidMagic()
    {
        try {
            // Provide 6 arbitrary bytes that do not match TrustStore magic
            TrustStore::fromBinary(BinaryString::fromString('foobar'));
            $this->fail('Expected InvalidArgumentException not thrown');
        } catch (\InvalidArgumentException $exception) {
            $this->assertEquals('Invalid magic bytes for ' . TrustStore::class, $exception->getMessage());
        }
    }

    public function testConstruct()
    {
        $store = new TrustStore([
            Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])),
        ]);

        $this->assertCount(1, $store->certificates);
        $this->assertEquals('Example Root CA Certificate', $store->certificates[0]->description);

        try {
            new TrustStore([
                Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[0])),
            ]);
            $this->fail('Expected InvalidArgumentException not thrown');
        } catch (\InvalidArgumentException $exception) {
            $this->assertEquals('Only self-signed root CA certificates can be added to trust store', $exception->getMessage());
        }

        try {
            new TrustStore([
                Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])),
                Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERTS[1])),
            ]);
            $this->fail('Expected InvalidArgumentException not thrown');
        } catch (\InvalidArgumentException $exception) {
            $this->assertEquals('Certificates in trust store must have unique KeyIds', $exception->getMessage());
        }
    }
}
