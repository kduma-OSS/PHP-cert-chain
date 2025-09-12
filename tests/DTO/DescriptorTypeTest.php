<?php

namespace KDuma\CertificateChainOfTrust\Tests\DTO;

use KDuma\CertificateChainOfTrust\DTO\DescriptorType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(DescriptorType::class)]
class DescriptorTypeTest extends TestCase
{

    public function testFromByte()
    {
        $this->assertEquals(DescriptorType::USERNAME, DescriptorType::fromByte(0x01));
        $this->assertEquals(DescriptorType::EMAIL, DescriptorType::fromByte(0x02));
        $this->assertEquals(DescriptorType::DOMAIN, DescriptorType::fromByte(0x03));

        try {
            DescriptorType::fromByte(0xFF);
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals("Invalid descriptor type: 0xff", $e->getMessage());
        }
    }

    public function testToString()
    {
        $this->assertEquals('Username', DescriptorType::USERNAME->toString());
        $this->assertEquals('Email', DescriptorType::EMAIL->toString());
        $this->assertEquals('Domain', DescriptorType::DOMAIN->toString());
    }
}
