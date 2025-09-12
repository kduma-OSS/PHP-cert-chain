<?php

namespace KDuma\CertificateChainOfTrust\Tests\DTO;

use KDuma\CertificateChainOfTrust\DTO\CertificateFlag;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CertificateFlag::class)]
class CertificateFlagTest extends TestCase
{

    public function testToString()
    {
        $this->assertEquals('Root CA', CertificateFlag::ROOT_CA->toString());
        $this->assertEquals('Intermediate CA', CertificateFlag::INTERMEDIATE_CA->toString());
        $this->assertEquals('CA', CertificateFlag::CA->toString());
        $this->assertEquals('Document Signer', CertificateFlag::DOCUMENT_SIGNER->toString());
        $this->assertEquals('Template Signer', CertificateFlag::TEMPLATE_SIGNER->toString());
    }

    public function testFromByte()
    {
        $this->assertEquals(CertificateFlag::ROOT_CA, CertificateFlag::fromByte(0x0001));
        $this->assertEquals(CertificateFlag::INTERMEDIATE_CA, CertificateFlag::fromByte(0x0002));
        $this->assertEquals(CertificateFlag::CA, CertificateFlag::fromByte(0x0004));
        $this->assertEquals(CertificateFlag::DOCUMENT_SIGNER, CertificateFlag::fromByte(0x0100));
        $this->assertEquals(CertificateFlag::TEMPLATE_SIGNER, CertificateFlag::fromByte(0x0200));

        try {
            CertificateFlag::fromByte(0xFFFF);
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals("Invalid flag: 0xffff", $e->getMessage());
        }
    }
}
