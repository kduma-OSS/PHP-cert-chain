<?php

namespace KDuma\CertificateChainOfTrust\Tests\DTO;

use KDuma\CertificateChainOfTrust\DTO\DescriptorType;
use KDuma\CertificateChainOfTrust\DTO\UserDescriptor;
use PHPUnit\Framework\TestCase;

class UserDescriptorTest extends TestCase
{

    public function test__construct()
    {
        $descriptor = new UserDescriptor(DescriptorType::USERNAME, 'johndoe');
        $this->assertEquals('johndoe', $descriptor->value);
        $this->assertEquals(DescriptorType::USERNAME, $descriptor->type);

        try {
            new UserDescriptor(DescriptorType::USERNAME, '');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Descriptor value cannot be empty', $e->getMessage());
        }
        
        try {
            new UserDescriptor(DescriptorType::USERNAME, "\x80\x81");
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Descriptor value must be valid UTF-8', $e->getMessage());
        }
    }

    public function testEquals()
    {
        $descriptor1 = new UserDescriptor(DescriptorType::USERNAME, 'johndoe');
        $descriptor2 = new UserDescriptor(DescriptorType::USERNAME, 'johndoe');
        $descriptor3 = new UserDescriptor(DescriptorType::EMAIL, 'john@doe.com');

        $this->assertTrue($descriptor1->equals($descriptor2));
        $this->assertFalse($descriptor1->equals($descriptor3));
    }

    public function testToString()
    {
        $descriptor = new UserDescriptor(DescriptorType::USERNAME, 'johndoe');
        $this->assertEquals('Username: johndoe', $descriptor->toString());

        $descriptor = new UserDescriptor(DescriptorType::EMAIL, 'john@doe.com');
        $this->assertEquals('Email: john@doe.com', $descriptor->toString());

        $descriptor = new UserDescriptor(DescriptorType::DOMAIN, 'doe.com');
        $this->assertEquals('Domain: doe.com', $descriptor->toString());
    }
}
