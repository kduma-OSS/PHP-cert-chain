<?php

namespace KDuma\CertificateChainOfTrust\Tests\Crypto;

use KDuma\CertificateChainOfTrust\Crypto\Ed25519;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Ed25519::class)]
class Ed25519Test extends TestCase
{
    public function testMakeKeyPair()
    {
        $pair = Ed25519::makeKeyPair();

        $this->assertEquals(16, $pair->id->size());
        $this->assertEquals(32, $pair->publicKey->size());
        $this->assertEquals(64, $pair->privateKey->size());
    }
}
