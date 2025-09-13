<?php

namespace KDuma\CertificateChainOfTrust\Tests\DTO;

use KDuma\CertificateChainOfTrust\Crypto\Ed25519;
use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PrivateKeyPair;
use KDuma\CertificateChainOfTrust\DTO\DescriptorType;
use KDuma\CertificateChainOfTrust\DTO\Signature;
use KDuma\CertificateChainOfTrust\DTO\UserDescriptor;
use KDuma\BinaryTools\BinaryReader;
use KDuma\BinaryTools\BinaryString;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Signature::class)]
class SignatureTest extends TestCase
{
    const string SIGNATURE_HEX = '10d7f832df347ca6d99ddab85b3887db3540facdbc928883aedca0b1141325a8227241c10e888279ec02420f4b8878c6827dfde924543e8a7cdc5df192dc4631c1bd6e9ec9c9a81fc7383b0606578cd7b306';
    const string FIXED_SIGNATURE_HEX = 'd7f832df347ca6d99ddab85b3887db35facdbc928883aedca0b1141325a8227241c10e888279ec02420f4b8878c6827dfde924543e8a7cdc5df192dc4631c1bd6e9ec9c9a81fc7383b0606578cd7b306';
    private PrivateKeyPair $key;
    private BinaryString $data;
    private Signature $signature;

    protected function setUp(): void
    {
        $this->key = PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKENf4Mt80fKbZndq4WziH2zUAIMNIwfS7VADNKBb14ZjQUJrtSptgu8/B0ElVStKE6g5XAEAH1SWnxwLKT/Xy4fp4gSlxSzDKq/Q9Oprda/NAuhACAsNIwfS7VADNKBb14ZjQUJrtSptgu8/B0ElVStKE6g5X'));
        $this->data = new BinaryString("TEST");
        $this->signature = Signature::fromBinary(BinaryString::fromHex(self::SIGNATURE_HEX));

        parent::setUp();
    }

    public function test__construct()
    {
        $this->assertEquals($this->key->id, $this->signature->keyId);
        $this->assertEquals(BinaryString::fromHex(self::SIGNATURE_HEX), $this->signature->toBinary());

        try {
            new Signature(new KeyId(''), $this->signature->signature);
            $this->fail('Expected exception not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Signer KeyId cannot be empty', $e->getMessage());
        }

        try {
            new Signature($this->signature->keyId, new BinaryString(''));
            $this->fail('Expected exception not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Signature cannot be empty', $e->getMessage());
        }
    }

    public function testEquals()
    {
        $same = new Signature($this->signature->keyId, $this->signature->signature);
        $differentKeyId = new Signature(new KeyId(str_repeat("\x00", 16)), $this->signature->signature);
        $differentSignature = new Signature($this->signature->keyId, new BinaryString(str_repeat("\x00", 64)));

        $this->assertTrue($this->signature->equals($same));
        $this->assertFalse($this->signature->equals($differentKeyId));
        $this->assertFalse($this->signature->equals($differentSignature));
    }

    public function testFromBinary()
    {
        $this->assertEquals($this->signature, Signature::fromBinary(BinaryString::fromHex(self::SIGNATURE_HEX)));
    }

    public function testFromBinaryReader()
    {
        $reader = new BinaryReader(BinaryString::fromHex(self::SIGNATURE_HEX));
        $signature = Signature::fromBinaryReader($reader);
        $this->assertEquals($this->signature, $signature);
        $this->assertEquals($reader->length, $reader->position);

        $reader = new BinaryReader(BinaryString::fromHex(self::FIXED_SIGNATURE_HEX));
        $signature = Signature::fromBinaryReader($reader, true);
        $this->assertEquals($this->signature, $signature);
        $this->assertEquals($reader->length, $reader->position);

        try {
            $reader = new BinaryReader(BinaryString::fromHex(substr(self::SIGNATURE_HEX, 0, -2))); // incomplete
            Signature::fromBinaryReader($reader);
            $this->fail('Expected exception not thrown');
        } catch (\RuntimeException $e) {
            $this->assertEquals('Unexpected end of data while reading 64 bytes', $e->getMessage());
            $this->assertEquals(0, $reader->position); // position should be rewound
        }
    }

    public function testToBinary()
    {
        $this->assertEquals(self::SIGNATURE_HEX, $this->signature->toBinary()->toHex());
        $this->assertEquals(self::FIXED_SIGNATURE_HEX, $this->signature->toBinary(true)->toHex());

        try {
            $invalidSignature = new Signature($this->signature->keyId, new BinaryString('short'));
            $invalidSignature->toBinary(true);
            $this->fail('Expected exception not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Signature must be 64 bytes for fixed length encoding', $e->getMessage());
        }

        try {
            $invalidKeyId = new Signature(new KeyId('short'), $this->signature->signature);
            $invalidKeyId->toBinary(true);
            $this->fail('Expected exception not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('KeyId must be 16 bytes for fixed length encoding', $e->getMessage());
        }
    }

    public function testMake()
    {
        $signature = Signature::make($this->data, $this->key);
        $this->assertEquals($this->key->id, $signature->keyId);

        $this->assertEquals($this->signature, $signature);
    }

    public function testValidate()
    {
        $this->assertTrue($this->signature->validate($this->data, $this->key));
        $this->assertTrue($this->signature->validate($this->data, $this->key->toPublicKey()));
        $this->assertFalse($this->signature->validate(BinaryString::fromString('OTHER'), $this->key->toPublicKey()));

        try {
            $this->signature->validate($this->data, Ed25519::makeKeyPair());
            $this->fail('Expected exception not thrown');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('KeyId does not match the provided key', $e->getMessage());
        }
    }
}
