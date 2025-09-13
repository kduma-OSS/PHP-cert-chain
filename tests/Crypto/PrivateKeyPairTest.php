<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\Tests\Crypto;

use KDuma\BinaryTools\BinaryString;
use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PrivateKeyPair;
use KDuma\CertificateChainOfTrust\Crypto\PublicKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PrivateKeyPair::class)]
class PrivateKeyPairTest extends TestCase
{
    public const string KEY_ID_HEX = 'a503e0452f4d3a8539c791b0e958069d';
    public const string PUBLIC_KEY_HEX = '6ba8dfa86878b025e49d9858b66b20e5a89e96d9c656a989eec09f5d776ad593';
    public const string PRIVATE_KEY_HEX = 'b57cddc66aa709b4a58d920998ad0c95da6e807671024855687a0ff5d86491dc6ba8dfa86878b025e49d9858b66b20e5a89e96d9c656a989eec09f5d776ad593';
    public const string BINARY_B64 = "PrivateKEKUD4EUvTTqFOceRsOlYBp0AIGuo36hoeLAl5J2YWLZrIOWonpbZxlapie7An113atWTAEC1fN3GaqcJtKWNkgmYrQyV2m6AdnECSFVoeg/12GSR3Guo36hoeLAl5J2YWLZrIOWonpbZxlapie7An113atWT";

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
            $this->assertEquals('Failed to parse PrivateKey: Unexpected end of data while reading 64 bytes', $exception->getMessage());
        }
    }

    public function testToPublicKey()
    {
        $this->assertEquals(
            new PublicKey(
                id: KeyId::fromHex(self::KEY_ID_HEX),
                publicKey: BinaryString::fromHex(self::PUBLIC_KEY_HEX)
            ),
            $this->key->toPublicKey()
        );
    }
}
