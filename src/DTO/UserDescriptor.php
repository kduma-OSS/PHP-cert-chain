<?php

namespace KDuma\CertificateChainOfTrust\DTO;


use KDuma\CertificateChainOfTrust\Utils\BinaryReader;
use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use KDuma\CertificateChainOfTrust\Utils\BinaryWriter;

readonly class UserDescriptor
{
    public function __construct(
        public DescriptorType $type,
        public string         $value
    ) {
        if (empty($value)) {
            throw new \InvalidArgumentException('Descriptor value cannot be empty');
        }

        if (!mb_check_encoding($value, 'UTF-8')) {
            throw new \InvalidArgumentException('Descriptor value must be valid UTF-8');
        }
    }

    public function toString(): string
    {
        return $this->type->toString() . ': ' . $this->value;
    }

    public function equals(UserDescriptor $other): bool
    {
        return $this->type === $other->type && $this->value === $other->value;
    }

    public function toBinary(): BinaryString
    {
        $writer = new BinaryWriter();
        $writer->writeByte($this->type->value);
        $writer->writeStringWithLength(BinaryString::fromString($this->value), true);

        return $writer->getBuffer();
    }

    public static function fromBinaryReader(BinaryReader $reader): self
    {
        $type = DescriptorType::from($reader->readByte());
        try {
            $value = $reader->readStringWithLength(true)->toString();
        } catch (\RuntimeException $e) {
            $reader->position -= 1; // rewind to before reading type
            throw $e;
        }

        return new self($type, $value);
    }

    public static function fromBinary(BinaryString $binary): self
    {
        $reader = new BinaryReader($binary);
        return self::fromBinaryReader($reader);
    }
}