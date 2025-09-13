<?php

namespace KDuma\CertificateChainOfTrust;

use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\BinaryTools\BinaryReader;
use KDuma\BinaryTools\BinaryString;
use KDuma\BinaryTools\BinaryWriter;

abstract readonly class CertificatesContainer
{
    public function __construct(
        /** @var Certificate[] */
        public array $certificates = [],
    )
    {
        if (array_any($this->certificates, fn($certificate) => !$certificate instanceof Certificate)) {
            throw new \InvalidArgumentException('All elements of $certificates must be instances of Certificate');
        }

        foreach ($this->certificates as $certificate) {
            $this->validateAddedCertificate($certificate);
        }
    }

    abstract protected function validateAddedCertificate(Certificate $certificate): void;

    abstract protected static function getMagicBytes(): string;

    public static function fromBinary(BinaryString $data): static
    {
        $reader = new BinaryReader($data);

        $requiredMagic = BinaryString::fromString(static::getMagicBytes());
        if($requiredMagic->size() > 0) {
            $actualMagic = $reader->readBytes($requiredMagic->size());
            if (!$actualMagic->equals($requiredMagic)) {
                throw new \InvalidArgumentException('Invalid magic bytes for ' . static::class);
            }
        }

        $certificates = [];
        while ($reader->has_more_data) {
            $certificates[] = Certificate::fromBinaryReader($reader);
        }

        return new static($certificates);
    }

    public function toBinary(): BinaryString
    {
        $writer = new BinaryWriter();

        $writer->writeBytes(BinaryString::fromString(static::getMagicBytes()));

        foreach ($this->certificates as $certificate) {
            $writer->writeBytes($certificate->toBinary());
        }

        return $writer->getBuffer();
    }

    public function getFirstCertificate(): ?Certificate
    {
        return $this->certificates[0] ?? null;
    }

    public function getById(KeyId $id): ?Certificate
    {
        return array_find($this->certificates, fn($certificate) => $certificate->key->id->equals($id));
    }
}