<?php

namespace KDuma\CertificateChainOfTrust\DTO;

enum CertificateFlag: int
{
    case ROOT_CA = 0x0001;
    case INTERMEDIATE_CA = 0x0002;
    case CA = 0x0004;
    case DOCUMENT_SIGNER = 0x0100;
    case TEMPLATE_SIGNER = 0x0200;

    public function toString(): string
    {
        return match ($this) {
            self::ROOT_CA => 'Root CA',
            self::INTERMEDIATE_CA => 'Intermediate CA',
            self::CA => 'CA',
            self::DOCUMENT_SIGNER => 'Document Signer',
            self::TEMPLATE_SIGNER => 'Template Signer',
        };
    }

    public static function fromByte(int $byte): self
    {
        return self::tryFrom($byte) ?? throw new \InvalidArgumentException("Invalid flag: 0x" . dechex($byte));
    }
}