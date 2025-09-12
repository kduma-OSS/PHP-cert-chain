<?php

namespace KDuma\CertificateChainOfTrust\Tests\Enums;

use KDuma\CertificateChainOfTrust\Enums\CertificateFlag;
use KDuma\CertificateChainOfTrust\Enums\CertificateFlagsCollection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CertificateFlagsCollection::class)]
class CertificateFlagsCollectionTest extends TestCase
{
    public function testEndEntityFlags()
    {
        $this->assertEquals(0x0300, CertificateFlagsCollection::EndEntityFlags()->value);
    }
    public function testCAFlags()
    {
        $this->assertEquals(0x0007, CertificateFlagsCollection::CAFlags()->value);
    }
    public function testFromInt()
    {
        $this->assertEquals(0x0000, CertificateFlagsCollection::fromInt(0x0000)->value);
    }

    public function testFromList()
    {
        $this->assertEquals(0x0000, CertificateFlagsCollection::fromList([])->value);

        $this->assertEquals(CertificateFlag::CA->value && CertificateFlag::DOCUMENT_SIGNER->value, CertificateFlagsCollection::fromList([
            CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER
        ])->value);

        try {
            CertificateFlagsCollection::fromList([CertificateFlag::CA, 'invalid']);
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('All elements must be instances of CertificateFlag enum', $e->getMessage());
        }
    }

    public function testHas()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertTrue($collection->has(CertificateFlag::CA));
        $this->assertTrue($collection->has(CertificateFlag::DOCUMENT_SIGNER));
        $this->assertFalse($collection->has(CertificateFlag::TEMPLATE_SIGNER));
    }

    public function testHasRootCA()
    {
        $collection = CertificateFlagsCollection::fromList([]);
        $this->assertFalse($collection->hasRootCA());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::ROOT_CA]);
        $this->assertTrue($collection->hasRootCA());
    }

    public function testHasCA()
    {
        $collection = CertificateFlagsCollection::fromList([]);
        $this->assertFalse($collection->hasCA());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA]);
        $this->assertTrue($collection->hasCA());
    }

    public function testHasIntermediateCA()
    {
        $collection = CertificateFlagsCollection::fromList([]);
        $this->assertFalse($collection->hasIntermediateCA());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::INTERMEDIATE_CA]);
        $this->assertTrue($collection->hasIntermediateCA());
    }

    public function testHasTemplateSigner()
    {
        $collection = CertificateFlagsCollection::fromList([]);
        $this->assertFalse($collection->hasTemplateSigner());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::TEMPLATE_SIGNER]);
        $this->assertTrue($collection->hasTemplateSigner());
    }

    public function testHasDocumentSigner()
    {
        $collection = CertificateFlagsCollection::fromList([]);
        $this->assertFalse($collection->hasDocumentSigner());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertTrue($collection->hasDocumentSigner());
    }

    public function testIsCA()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertTrue($collection->isCA());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertTrue($collection->isCA());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertTrue($collection->isCA());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertFalse($collection->isCA());
    }

    public function testGetCAFlags()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertEquals(CertificateFlag::CA->value, $collection->getCAFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::ROOT_CA, CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertEquals(CertificateFlag::ROOT_CA->value, $collection->getCAFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertEquals(CertificateFlag::INTERMEDIATE_CA->value, $collection->getCAFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertEquals(CertificateFlag::ROOT_CA->value | CertificateFlag::INTERMEDIATE_CA->value, $collection->getCAFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertEquals(0x0000, $collection->getCAFlags()->value);
    }

    public function testGetEndEntityFlags()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::DOCUMENT_SIGNER, CertificateFlag::TEMPLATE_SIGNER, CertificateFlag::CA]);
        $this->assertEquals(CertificateFlag::DOCUMENT_SIGNER->value | CertificateFlag::TEMPLATE_SIGNER->value, $collection->getEndEntityFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertEquals(CertificateFlag::DOCUMENT_SIGNER->value, $collection->getEndEntityFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::TEMPLATE_SIGNER, CertificateFlag::CA]);
        $this->assertEquals(CertificateFlag::TEMPLATE_SIGNER->value, $collection->getEndEntityFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA]);
        $this->assertEquals(0x0000, $collection->getEndEntityFlags()->value);
    }

    public function testToString()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER]);
        $this->assertEquals('CA | Document Signer', $collection->toString());

        $collection = CertificateFlagsCollection::fromList([]);
        $this->assertEquals('', $collection->toString());
    }

    public function testIsSubsetOf()
    {
        $collectionA = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER]);
        $collectionB = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::DOCUMENT_SIGNER, CertificateFlag::TEMPLATE_SIGNER]);
        $collectionC = CertificateFlagsCollection::fromList([CertificateFlag::CA]);

        $this->assertTrue($collectionA->isSubsetOf($collectionB));
        $this->assertFalse($collectionB->isSubsetOf($collectionA));
        $this->assertFalse($collectionA->isSubsetOf($collectionC));
    }
}
