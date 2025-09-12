<?php

namespace KDuma\CertificateChainOfTrust\Tests\Crypto;

use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PublicKey;
use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PublicKey::class)]
class PublicKeyTest extends TestCase
{
    const string KEY_ID_HEX = '4773d12e2371bb935b9a0f5439b4a1c3';
    const string PUBLIC_KEY_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
    const string BINARY_B64 = "PubKEEdz0S4jcbuTW5oPVDm0ocMAIAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/";

    private PublicKey $publicKey;

    protected function setUp(): void
    {
        $this->publicKey = new PublicKey(
            id: KeyId::fromHex(self::KEY_ID_HEX),
            publicKey: BinaryString::fromHex(self::PUBLIC_KEY_HEX),
        );

        parent::setUp();
    }

    public function testToBinary()
    {
        $this->assertEquals(
            self::BINARY_B64,
            $this->publicKey->toBinary()->toBase64()
        );
    }

    public function testToArray()
    {
        $this->assertEquals(
            [
                'id' => self::KEY_ID_HEX,
                'publicKey' => self::PUBLIC_KEY_HEX,
            ],
            $this->publicKey->toArray()
        );
    }

    public function testIsKeyIdValid()
    {
        $this->assertTrue(
            $this->publicKey->isKeyIdValid()
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
            $this->publicKey
        );
    }
}
