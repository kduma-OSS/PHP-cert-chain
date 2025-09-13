<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\DTO;

enum CertificateFlag: int
{
    case ROOT_CA = 0x0001;
    case INTERMEDIATE_CA = 0x0002;
    case CA = 0x0004;
    case END_ENTITY_FLAG_1 = 0x0100;
    case END_ENTITY_FLAG_2 = 0x0200;
    case END_ENTITY_FLAG_3 = 0x0400;
    case END_ENTITY_FLAG_4 = 0x0800;
    case END_ENTITY_FLAG_5 = 0x1000;
    case END_ENTITY_FLAG_6 = 0x2000;
    case END_ENTITY_FLAG_7 = 0x4000;
    case END_ENTITY_FLAG_8 = 0x8000;

    public function toString(): string
    {
        return match ($this) {
            self::ROOT_CA => 'Root CA',
            self::INTERMEDIATE_CA => 'Intermediate CA',
            self::CA => 'CA',
            self::END_ENTITY_FLAG_1 => 'End Entity Flag 1',
            self::END_ENTITY_FLAG_2 => 'End Entity Flag 2',
            self::END_ENTITY_FLAG_3 => 'End Entity Flag 3',
            self::END_ENTITY_FLAG_4 => 'End Entity Flag 4',
            self::END_ENTITY_FLAG_5 => 'End Entity Flag 5',
            self::END_ENTITY_FLAG_6 => 'End Entity Flag 6',
            self::END_ENTITY_FLAG_7 => 'End Entity Flag 7',
            self::END_ENTITY_FLAG_8 => 'End Entity Flag 8',
        };
    }

    public static function fromByte(int $byte): self
    {
        return self::tryFrom($byte) ?? throw new \InvalidArgumentException("Invalid flag: 0x" . dechex($byte));
    }
}
