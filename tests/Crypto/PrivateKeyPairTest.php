<?php

namespace KDuma\CertificateChainOfTrust\Tests\Crypto;

use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PrivateKeyPair;
use KDuma\CertificateChainOfTrust\Crypto\PublicKey;
use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PrivateKeyPair::class)]
class PrivateKeyPairTest extends TestCase
{
    const string KEY_ID_HEX = '4773d12e2371bb935b9a0f5439b4a1c3';
    const string PUBLIC_KEY_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
    const string PRIVATE_KEY_HEX = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';
    const string BINARY_B64 = "PrivateKEEdz0S4jcbuTW5oPVDm0ocMAIAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/ACD/7t3Mu6qZiHdmVUQzIhEA/+7dzLuqmYh3ZlVEMyIRAA==";

    private PublicKey $key;

    protected function setUp(): void
    {
        $this->key = new PrivateKeyPair(
            id: KeyId::fromHex(self::KEY_ID_HEX),
            publicKey: BinaryString::fromHex(self::PUBLIC_KEY_HEX),
            privateKey: BinaryString::fromHex(self::PRIVATE_KEY_HEX)
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
                'privateKey' => self::PRIVATE_KEY_HEX,
            ],
            $this->key->toArray()
        );
    }

    public function testFromArray()
    {
        $reconstructedPrivateKey = PrivateKeyPair::fromArray([
            'id' => self::KEY_ID_HEX,
            'publicKey' => self::PUBLIC_KEY_HEX,
            'privateKey' => self::PRIVATE_KEY_HEX,
        ]);

        $this->assertEquals(
            $reconstructedPrivateKey,
            $this->key
        );
    }

    public function testFromBinary()
    {
        $reconstructedPrivateKey = PrivateKeyPair::fromBinary(BinaryString::fromBase64(self::BINARY_B64));
        $this->assertEquals(
            $reconstructedPrivateKey,
            $this->key
        );

        try {
            PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateXAAAAAA'));
            $this->fail("Expected exception not thrown");
        } catch (\InvalidArgumentException $exception) {
            $this->assertEquals('Invalid magic bytes for PrivateKey', $exception->getMessage());
        }

        try {
            PrivateKeyPair::fromBinary(BinaryString::fromBase64(trim(self::BINARY_B64, '=').'PrivateXAAAAAA'));
            $this->fail("Expected exception not thrown");
        } catch (\InvalidArgumentException $exception) {
            $this->assertEquals('Extra data found after parsing PrivateKey', $exception->getMessage());
        }

        try {
            PrivateKeyPair::fromBinary(BinaryString::fromBase64(substr(self::BINARY_B64, 0, -4)));
            $this->fail("Expected exception not thrown");
        } catch (\InvalidArgumentException $exception) {
            $this->assertEquals('Failed to parse PrivateKey: Unexpected end of data while reading 32 bytes', $exception->getMessage());
        }
    }
}
