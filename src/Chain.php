<?php

namespace KDuma\CertificateChainOfTrust;

use KDuma\CertificateChainOfTrust\Utils\BinaryReader;
use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use KDuma\CertificateChainOfTrust\Utils\BinaryWriter;

readonly class Chain
{
    public function __construct(
        /** @var Certificate[] */
        public array $certificates = [],
    )
    {
        if (array_any($this->certificates, fn($certificate) => !$certificate instanceof Certificate)) {
            throw new \InvalidArgumentException('All elements of $certificates must be instances of Certificate');
        }
    }

    public static function fromBinary(BinaryString $data): static
    {
        $reader = new BinaryReader($data);
        return self::fromBinaryReader($reader);
    }

    public static function fromBinaryReader(BinaryReader $reader): self
    {
        $certificates = [];
        while ($reader->has_more_data) {
            $certificates[] = Certificate::fromBinaryReader($reader);
        }

        return new self($certificates);
    }

    public function toBinary(): BinaryString
    {
        $writer = new BinaryWriter();

        foreach ($this->certificates as $certificate) {
            $writer->writeBytes($certificate->toBinary());
        }

        return $writer->getBuffer();
    }
}