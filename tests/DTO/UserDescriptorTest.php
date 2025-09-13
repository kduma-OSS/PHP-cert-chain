<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\Tests\DTO;

use KDuma\BinaryTools\BinaryReader;
use KDuma\BinaryTools\BinaryString;
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

    public function testToBinary()
    {
        $descriptor = new UserDescriptor(DescriptorType::USERNAME, 'johndoe');
        $this->assertEquals('0100076a6f686e646f65', $descriptor->toBinary()->toHex());
    }

    public function testFromBinaryReader()
    {
        $reader = new BinaryReader(BinaryString::fromHex('0100076a6f686e646f65'));
        $descriptor = UserDescriptor::fromBinaryReader($reader);
        $this->assertEquals(new UserDescriptor(DescriptorType::USERNAME, 'johndoe'), $descriptor);
        $this->assertEquals($reader->length, $reader->position);

        try {
            $reader = new BinaryReader(BinaryString::fromHex('0100076a6f686e646f')); // incomplete
            UserDescriptor::fromBinaryReader($reader);
            $this->fail('Expected exception not thrown');
        } catch (\RuntimeException $e) {
            $this->assertEquals('Unexpected end of data while reading 7 bytes', $e->getMessage());
            $this->assertEquals(0, $reader->position); // position should be rewound
        }
    }

    public function testFromBinary()
    {
        $descriptor = UserDescriptor::fromBinary(BinaryString::fromHex('0100076a6f686e646f65'));
        $this->assertEquals(new UserDescriptor(DescriptorType::USERNAME, 'johndoe'), $descriptor);
    }
}
