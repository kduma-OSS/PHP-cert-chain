<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\Tests\DTO;

use KDuma\CertificateChainOfTrust\DTO\CertificateFlag;
use KDuma\CertificateChainOfTrust\DTO\CertificateFlagsCollection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CertificateFlagsCollection::class)]
class CertificateFlagsCollectionTest extends TestCase
{
    public function testEndEntityFlags()
    {
        $this->assertEquals(0xFF00, CertificateFlagsCollection::EndEntityFlags()->value);
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

        $this->assertEquals(CertificateFlag::CA->value && CertificateFlag::END_ENTITY_FLAG_1->value, CertificateFlagsCollection::fromList([
            CertificateFlag::CA, CertificateFlag::END_ENTITY_FLAG_1
        ])->value);

        try {
            CertificateFlagsCollection::fromList([CertificateFlag::CA, 'invalid']);
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('All elements must be instances of CertificateFlag enum', $e->getMessage());
        }
    }

    public function testHas()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertTrue($collection->has(CertificateFlag::CA));
        $this->assertTrue($collection->has(CertificateFlag::END_ENTITY_FLAG_1));
        $this->assertFalse($collection->has(CertificateFlag::END_ENTITY_FLAG_2));
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

    public function testHasEndEntityFlag2()
    {
        $collection = CertificateFlagsCollection::fromList([]);
        $this->assertFalse($collection->has(CertificateFlag::END_ENTITY_FLAG_2));

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::END_ENTITY_FLAG_2]);
        $this->assertTrue($collection->has(CertificateFlag::END_ENTITY_FLAG_2));
    }

    public function testHasEndEntityFlag1()
    {
        $collection = CertificateFlagsCollection::fromList([]);
        $this->assertFalse($collection->has(CertificateFlag::END_ENTITY_FLAG_1));

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertTrue($collection->has(CertificateFlag::END_ENTITY_FLAG_1));
    }

    public function testIsCA()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertTrue($collection->isCA());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::ROOT_CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertTrue($collection->isCA());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::INTERMEDIATE_CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertTrue($collection->isCA());

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertFalse($collection->isCA());
    }

    public function testGetCAFlags()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertEquals(CertificateFlag::CA->value, $collection->getCAFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::ROOT_CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertEquals(CertificateFlag::ROOT_CA->value, $collection->getCAFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::INTERMEDIATE_CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertEquals(CertificateFlag::INTERMEDIATE_CA->value, $collection->getCAFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertEquals(CertificateFlag::ROOT_CA->value | CertificateFlag::INTERMEDIATE_CA->value, $collection->getCAFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertEquals(0x0000, $collection->getCAFlags()->value);
    }

    public function testGetEndEntityFlags()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::END_ENTITY_FLAG_1, CertificateFlag::END_ENTITY_FLAG_2, CertificateFlag::CA]);
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_1->value | CertificateFlag::END_ENTITY_FLAG_2->value, $collection->getEndEntityFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_1->value, $collection->getEndEntityFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::END_ENTITY_FLAG_2, CertificateFlag::CA]);
        $this->assertEquals(CertificateFlag::END_ENTITY_FLAG_2->value, $collection->getEndEntityFlags()->value);

        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA]);
        $this->assertEquals(0x0000, $collection->getEndEntityFlags()->value);
    }

    public function testToString()
    {
        $collection = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $this->assertEquals('CA | End Entity Flag 1', $collection->toString());

        $collection = CertificateFlagsCollection::fromList([]);
        $this->assertEquals('', $collection->toString());
    }

    public function testIsSubsetOf()
    {
        $collectionA = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::END_ENTITY_FLAG_1]);
        $collectionB = CertificateFlagsCollection::fromList([CertificateFlag::CA, CertificateFlag::END_ENTITY_FLAG_1, CertificateFlag::END_ENTITY_FLAG_2]);
        $collectionC = CertificateFlagsCollection::fromList([CertificateFlag::CA]);

        $this->assertTrue($collectionA->isSubsetOf($collectionB));
        $this->assertFalse($collectionB->isSubsetOf($collectionA));
        $this->assertFalse($collectionA->isSubsetOf($collectionC));
    }
}
