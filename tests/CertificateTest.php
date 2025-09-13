<?php

namespace KDuma\CertificateChainOfTrust\Tests;

use KDuma\BinaryTools\BinaryReader;
use KDuma\BinaryTools\BinaryString;
use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PublicKey;
use KDuma\CertificateChainOfTrust\DTO\CertificateFlagsCollection;
use KDuma\CertificateChainOfTrust\DTO\DescriptorType;
use KDuma\CertificateChainOfTrust\DTO\Signature;
use KDuma\CertificateChainOfTrust\DTO\UserDescriptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Certificate::class)]
class CertificateTest extends TestCase
{
    public const string EXAMPLE_CERT = 'CERTAeNW45NAy3hEziID7lvCsfZ3EMHnQFCvqUxr07jGQXyl8wQ83TpNGnOCEGxOUYg1CCNFeGFtcGxlIEludGVybWVkaWF0ZSBDQSBDZXJ0aWZpY2F0ZQEDABhpbnRlcm1lZGlhdGUuZXhhbXBsZS5jb20DBgFY0TIpXLtX/tk79S+G+oCdPB8ECk4b15eCMYPFAuBxipqF2Nwjj847RvLaw08DPHu7/7Uh7U1QdfntbO5sJLbw2bXx6d5PaaGKpGOnqOrGBQ==';
    public const string EXAMPLE_ROOT_CERT = 'CERTAVjRMilcu1f+2Tv1L4b6gJ3HVeE/YCex4hSFvT1RjNnhtRZovhI8NjSj2rUiiOiTCxtFeGFtcGxlIFJvb3QgQ0EgQ2VydGlmaWNhdGUBAwAQcm9vdC5leGFtcGxlLmNvbQMHAVjRMilcu1f+2Tv1L4b6gJ0eZuMAzrTmI10gs8GZjruuy5tlczYYcRnV9UN4r+fCo05FEqmui2/WJVVBi2Nj+H3DaMrlRC62so24CSta31AH';

    public function testGetSelfSignature()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $this->assertNull($cert->getSelfSignature());

        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_ROOT_CERT));
        $this->assertEquals('1058d132295cbb57fed93bf52f86fa809d401e66e300ceb4e6235d20b3c1998ebbaecb9b657336187119d5f54378afe7c2a34e4512a9ae8b6fd62555418b6363f87dc368cae5442eb6b28db8092b5adf5007', $cert->getSelfSignature()->toBinary()->toHex());
    }

    public function testIsSelfSigned()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $this->assertFalse($cert->isSelfSigned());

        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_ROOT_CERT));
        $this->assertTrue($cert->isSelfSigned());
    }

    public function testToBinaryForSigning()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $binaryForSigning = $cert->toBinaryForSigning();

        $this->assertEquals('08445301e356e39340cb7844ce2203ee5bc2b1f67710c1e74050afa94c6bd3b8c6417ca5f3043cdd3a4d1a7382106c4e51883508234578616d706c6520496e7465726d65646961746520434120436572746966696361746501030018696e7465726d6564696174652e6578616d706c652e636f6d0306', $binaryForSigning->toHex());
    }

    public function testFromBinaryReader()
    {
        $reader = new BinaryReader(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $cert = Certificate::fromBinaryReader($reader);

        $this->assertEquals('Example Intermediate CA Certificate', $cert->description);
        $this->assertEquals('intermediate.example.com', $cert->userDescriptors[0]->value);
        $this->assertFalse($cert->isSelfSigned());

        try {
            $reader = new BinaryReader(BinaryString::fromBase64("CERTEuM="));
            Certificate::fromBinaryReader($reader);
            $this->fail('Expected InvalidArgumentException for invalid certificate data');
        } catch (\Exception $e) {
            $this->assertEquals('Unsupported Certificate version: 0x12', $e->getMessage());
        }

        try {
            $reader = new BinaryReader(BinaryString::fromBase64("CERTAeP///8="));
            Certificate::fromBinaryReader($reader);
            $this->fail('Expected InvalidArgumentException for invalid certificate data');
        } catch (\Exception $e) {
            $this->assertEquals('Failed to parse Certificate: Unexpected end of data while reading 16 bytes', $e->getMessage());
        }

        try {
            $reader = new BinaryReader(BinaryString::fromBase64(self::EXAMPLE_ROOT_CERT.'AAAA'));
            Certificate::fromBinaryReader($reader);
            $this->fail('Expected InvalidArgumentException for invalid certificate data');
        } catch (\Exception $e) {
            $this->assertEquals('Extra data found after parsing Certificate', $e->getMessage());
        }
    }

    public function testGetSignatureByKeyId()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_ROOT_CERT));

        // Get signature by the certificate's own key ID (self-signature)
        $selfSignature = $cert->getSignatureByKeyId($cert->key->id);
        $this->assertNotNull($selfSignature);
        $this->assertEquals($cert->getSelfSignature(), $selfSignature);

        // Try with a non-existent key ID
        $fakeKeyId = KeyId::fromString(str_repeat("\x00", 16));
        $noSignature = $cert->getSignatureByKeyId($fakeKeyId);
        $this->assertNull($noSignature);
    }

    public function test__construct()
    {
        // Valid certificate construction
        $keyId = KeyId::fromString(str_repeat("\x01", 16));
        $publicKey = new PublicKey($keyId, BinaryString::fromString(str_repeat("\x02", 32)));
        $userDescriptors = [new UserDescriptor(DescriptorType::DOMAIN, 'example.com')];
        $flags = CertificateFlagsCollection::fromInt(0x0007);
        $signatures = [];

        $cert = new Certificate($publicKey, 'Test Certificate', $userDescriptors, $flags, $signatures);
        $this->assertEquals('Test Certificate', $cert->description);
        $this->assertEquals('example.com', $cert->userDescriptors[0]->value);

        // Test invalid key ID (empty)
        try {
            $emptyKeyId = KeyId::fromString('');
            $invalidPublicKey = new PublicKey($emptyKeyId, BinaryString::fromString(str_repeat("\x02", 32)));
            new Certificate($invalidPublicKey, 'Test', $userDescriptors, $flags, $signatures);
            $this->fail('Expected InvalidArgumentException for empty key ID');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('KeyId cannot be empty', $e->getMessage());
        }

        // Test invalid key ID (wrong size)
        try {
            $wrongSizeKeyId = KeyId::fromString(str_repeat("\x01", 10));
            $invalidPublicKey = new PublicKey($wrongSizeKeyId, BinaryString::fromString(str_repeat("\x02", 32)));
            new Certificate($invalidPublicKey, 'Test', $userDescriptors, $flags, $signatures);
            $this->fail('Expected InvalidArgumentException for wrong size key ID');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('KeyId must be 16 bytes', $e->getMessage());
        }

        // Test invalid public key (empty)
        try {
            $validKeyId = KeyId::fromString(str_repeat("\x01", 16));
            $invalidPublicKey = new PublicKey($validKeyId, BinaryString::fromString(''));
            new Certificate($invalidPublicKey, 'Test', $userDescriptors, $flags, $signatures);
            $this->fail('Expected InvalidArgumentException for empty public key');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Public key cannot be empty', $e->getMessage());
        }

        // Test invalid public key (wrong size)
        try {
            $validKeyId = KeyId::fromString(str_repeat("\x01", 16));
            $invalidPublicKey = new PublicKey($validKeyId, BinaryString::fromString(str_repeat("\x02", 20)));
            new Certificate($invalidPublicKey, 'Test', $userDescriptors, $flags, $signatures);
            $this->fail('Expected InvalidArgumentException for wrong size public key');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Public key must be 32 bytes', $e->getMessage());
        }

        // Test invalid description (empty)
        try {
            new Certificate($publicKey, '', $userDescriptors, $flags, $signatures);
            $this->fail('Expected InvalidArgumentException for empty description');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Description cannot be empty', $e->getMessage());
        }

        // Test invalid description (non-UTF-8)
        try {
            new Certificate($publicKey, "\xFF\xFE", $userDescriptors, $flags, $signatures);
            $this->fail('Expected InvalidArgumentException for non-UTF-8 description');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Description must be valid UTF-8', $e->getMessage());
        }

        // Test invalid user descriptors
        try {
            $invalidUserDescriptors = [new \stdClass()];
            new Certificate($publicKey, 'Test', $invalidUserDescriptors, $flags, $signatures);
            $this->fail('Expected InvalidArgumentException for invalid user descriptors');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('All elements of $userDescriptors must be instances of UserDescriptor', $e->getMessage());
        }

        // Test invalid signatures
        try {
            $invalidSignatures = [new \stdClass()];
            new Certificate($publicKey, 'Test', $userDescriptors, $flags, $invalidSignatures);
            $this->fail('Expected InvalidArgumentException for invalid signatures');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('All elements of $signatures must be instances of Signature', $e->getMessage());
        }
    }

    public function testToBinary()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $binary = $cert->toBinary();

        $this->assertNotEmpty($binary->value);

        // Should be able to reconstruct the same certificate
        $reconstructed = Certificate::fromBinary($binary);
        $this->assertEquals($cert->description, $reconstructed->description);
        $this->assertEquals($cert->key->id->value, $reconstructed->key->id->value);
        $this->assertEquals($cert->key->publicKey->value, $reconstructed->key->publicKey->value);
    }

    public function testIsRootCA()
    {
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $this->assertFalse($cert->isRootCA());

        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_ROOT_CERT));
        $this->assertTrue($cert->isRootCA());
    }

    public function testFromBinary()
    {
        // Test with intermediate certificate
        $cert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_CERT));
        $this->assertEquals('Example Intermediate CA Certificate', $cert->description);
        $this->assertFalse($cert->isSelfSigned());
        $this->assertFalse($cert->isRootCA());

        // Test with root certificate
        $rootCert = Certificate::fromBinary(BinaryString::fromBase64(self::EXAMPLE_ROOT_CERT));
        $this->assertEquals('Example Root CA Certificate', $rootCert->description);
        $this->assertTrue($rootCert->isSelfSigned());
        $this->assertTrue($rootCert->isRootCA());

        // Test invalid binary (wrong magic)
        try {
            $invalidMagic = BinaryString::fromString('ABC' . str_repeat('x', 100));
            Certificate::fromBinary($invalidMagic);
            $this->fail('Expected InvalidArgumentException for wrong magic bytes');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('Invalid magic bytes for Certificate', $e->getMessage());
        }
    }
}
