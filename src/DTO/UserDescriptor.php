<?php

namespace KDuma\CertificateChainOfTrust\DTO;


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
}