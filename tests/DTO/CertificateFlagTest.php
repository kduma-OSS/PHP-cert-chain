<?php declare(strict_types=1);

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
        $this->assertEquals('End Entity Flag 1', CertificateFlag::END_ENTITY_FLAG_1->toString());
        $this->assertEquals('End Entity Flag 2', CertificateFlag::END_ENTITY_FLAG_2->toString());
        $this->assertEquals('End Entity Flag 3', CertificateFlag::END_ENTITY_FLAG_3->toString());
        $this->assertEquals('End Entity Flag 4', CertificateFlag::END_ENTITY_FLAG_4->toString());
        $this->assertEquals('End Entity Flag 5', CertificateFlag::END_ENTITY_FLAG_5->toString());
        $this->assertEquals('End Entity Flag 6', CertificateFlag::END_ENTITY_FLAG_6->toString());
        $this->assertEquals('End Entity Flag 7', CertificateFlag::END_ENTITY_FLAG_7->toString());
        $this->assertEquals('End Entity Flag 8', CertificateFlag::END_ENTITY_FLAG_8->toString());
    }

    public function testFromByte()
    {
        $this->assertEquals(CertificateFlag::ROOT_CA, CertificateFlag::fromByte(0x0001));
        $this->assertEquals(CertificateFlag::INTERMEDIATE_CA, CertificateFlag::fromByte(0x0002));
        $this->assertEquals(CertificateFlag::CA, CertificateFlag::fromByte(0x0004));
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_1, CertificateFlag::fromByte(0x0100));
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_2, CertificateFlag::fromByte(0x0200));
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_3, CertificateFlag::fromByte(0x0400));
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_4, CertificateFlag::fromByte(0x0800));
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_5, CertificateFlag::fromByte(0x1000));
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_6, CertificateFlag::fromByte(0x2000));
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_7, CertificateFlag::fromByte(0x4000));
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_8, CertificateFlag::fromByte(0x8000));

        try {
            CertificateFlag::fromByte(0xFFFF);
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals("Invalid flag: 0xffff", $e->getMessage());
        }
    }
}
