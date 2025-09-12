<?php

namespace KDuma\CertificateChainOfTrust\Enums;

enum DescriptorType: int
{
    case USERNAME = 0x01;
    case EMAIL = 0x02;
    case DOMAIN = 0x03;

    public function toString(): string
    {
        return match ($this) {
            self::USERNAME => 'Username',
            self::EMAIL => 'Email',
            self::DOMAIN => 'Domain',
        };
    }

    public static function fromByte(int $byte): self
    {
        return self::tryFrom($byte) ?? throw new \InvalidArgumentException("Invalid descriptor type: 0x" . dechex($byte));
    }
}