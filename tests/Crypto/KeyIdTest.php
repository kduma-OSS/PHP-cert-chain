<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\Tests\Crypto;

use KDuma\BinaryTools\BinaryString;
use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeyId::class)]
class KeyIdTest extends TestCase
{
    public function testFromPublicKey()
    {
        $keyId = KeyId::fromPublicKey(BinaryString::fromHex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'));

        $this->assertEquals('4773d12e2371bb935b9a0f5439b4a1c3', $keyId->toHex());
    }
}
