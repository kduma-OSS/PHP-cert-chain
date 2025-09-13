<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\DTO;

class CertificateFlagsCollection
{
    public array $flags {
        get {
            $parts = [];

            foreach (CertificateFlag::cases() as $flag) {
                if ($this->has($flag)) {
                    $parts[] = $flag;
                }
            }

            return $parts;
        }
    }

    private function __construct(public readonly int $value)
    {
    }

    public static function EndEntityFlags(): self
    {
        return self::fromList([
            CertificateFlag::END_ENTITY_FLAG_1,
            CertificateFlag::END_ENTITY_FLAG_2,
            CertificateFlag::END_ENTITY_FLAG_3,
            CertificateFlag::END_ENTITY_FLAG_4,
            CertificateFlag::END_ENTITY_FLAG_5,
            CertificateFlag::END_ENTITY_FLAG_6,
            CertificateFlag::END_ENTITY_FLAG_7,
            CertificateFlag::END_ENTITY_FLAG_8,
        ]);
    }

    public static function CAFlags(): self
    {
        return self::fromList([
            CertificateFlag::ROOT_CA,
            CertificateFlag::INTERMEDIATE_CA,
            CertificateFlag::CA,
        ]);
    }

    public static function fromInt(int $value)
    {
        return new self($value);
    }

    public static function fromList(array $flags): self
    {
        $value = 0;
        foreach ($flags as $flag) {
            if (!$flag instanceof CertificateFlag) {
                throw new \InvalidArgumentException('All elements must be instances of CertificateFlag enum');
            }
            $value |= $flag->value;
        }

        return new self($value);
    }

    public function has(CertificateFlag $flag): bool
    {
        return ($this->value & $flag->value) !== 0;
    }

    public function hasRootCA(): bool
    {
        return $this->has(CertificateFlag::ROOT_CA);
    }

    public function hasIntermediateCA(): bool
    {
        return $this->has(CertificateFlag::INTERMEDIATE_CA);
    }

    public function hasCA(): bool
    {
        return $this->has(CertificateFlag::CA);
    }

    public function isCA(): bool
    {
        return $this->hasRootCA() || $this->hasIntermediateCA() || $this->hasCA();
    }

    public function getEndEntityFlags(): CertificateFlagsCollection
    {
        return CertificateFlagsCollection::fromList(array_filter($this->flags, function (CertificateFlag $flag) {
            return !in_array($flag, [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA], true);
        }));
    }

    public function getCAFlags(): CertificateFlagsCollection
    {
        return CertificateFlagsCollection::fromList(array_filter($this->flags, function (CertificateFlag $flag) {
            return in_array($flag, [CertificateFlag::ROOT_CA, CertificateFlag::INTERMEDIATE_CA, CertificateFlag::CA], true);
        }));
    }

    public function isSubsetOf(CertificateFlagsCollection $other): bool
    {
        return ($this->value & ~$other->value) === 0;
    }

    public function toString(): string
    {
        $parts = array_map(function (CertificateFlag $flag) {
            return $flag->toString();
        }, $this->flags);

        return implode(' | ', $parts) ?: '';
    }
}
