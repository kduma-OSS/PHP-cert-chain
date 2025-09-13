<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\Tests\Crypto;

use KDuma\BinaryTools\BinaryString;
use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PublicKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PublicKey::class)]
class PublicKeyTest extends TestCase
{
    public const string KEY_ID_HEX = 'a503e0452f4d3a8539c791b0e958069d';
    public const string PUBLIC_KEY_HEX = '6ba8dfa86878b025e49d9858b66b20e5a89e96d9c656a989eec09f5d776ad593';
    public const string BINARY_B64 = "PubKEKUD4EUvTTqFOceRsOlYBp0AIGuo36hoeLAl5J2YWLZrIOWonpbZxlapie7An113atWT";

    private PublicKey $key;

    protected function setUp(): void
    {
        $this->key = new PublicKey(
            id: KeyId::fromHex(self::KEY_ID_HEX),
            publicKey: BinaryString::fromHex(self::PUBLIC_KEY_HEX),
        );

        parent::setUp();
    }

    public function testToBinary()
    {
        $this->assertEquals(
            self::BINARY_B64,
            $this->key->toBinary()->toBase64()
        );
    }

    public function testToArray()
    {
        $this->assertEquals(
            [
                'id' => self::KEY_ID_HEX,
                'publicKey' => self::PUBLIC_KEY_HEX,
            ],
            $this->key->toArray()
        );
    }

    public function testIsKeyIdValid()
    {
        $this->assertTrue(
            $this->key->isKeyIdValid()
        );


        $publicKeyWithInvalidId = new PublicKey(
            id: KeyId::fromHex('00000000000000000000000000000000'),
            publicKey: BinaryString::fromHex(self::PUBLIC_KEY_HEX),
        );

        $this->assertFalse(
            $publicKeyWithInvalidId->isKeyIdValid()
        );
    }

    public function testFromArray()
    {
        $reconstructedPublicKey = PublicKey::fromArray([
            'id' => self::KEY_ID_HEX,
            'publicKey' => self::PUBLIC_KEY_HEX,
        ]);

        $this->assertEquals(
            $reconstructedPublicKey,
            $this->key
        );
    }

    public function testFromBinary()
    {
        $reconstructedPublicKey = PublicKey::fromBinary(BinaryString::fromBase64(self::BINARY_B64));
        $this->assertEquals(
            $reconstructedPublicKey,
            $this->key
        );

        try {
            PublicKey::fromBinary(BinaryString::fromBase64('PubXAAAA'));
            $this->fail("Expected exception not thrown");
        } catch (\InvalidArgumentException $exception) {
            $this->assertEquals('Invalid magic bytes for PublicKey', $exception->getMessage());
        }

        try {
            PublicKey::fromBinary(BinaryString::fromBase64(self::BINARY_B64.'PubXAAAA'));
            $this->fail("Expected exception not thrown");
        } catch (\InvalidArgumentException $exception) {
            $this->assertEquals('Extra data found after parsing PublicKey', $exception->getMessage());
        }

        try {
            PublicKey::fromBinary(BinaryString::fromBase64(substr(self::BINARY_B64, 0, -1)));
            $this->fail("Expected exception not thrown");
        } catch (\InvalidArgumentException $exception) {
            $this->assertEquals('Failed to parse PublicKey: Unexpected end of data while reading 32 bytes', $exception->getMessage());
        }
    }
}
