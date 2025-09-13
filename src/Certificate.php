<?php

namespace KDuma\CertificateChainOfTrust;

use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PublicKey;
use KDuma\CertificateChainOfTrust\DTO\CertificateFlagsCollection;
use KDuma\CertificateChainOfTrust\DTO\Signature;
use KDuma\CertificateChainOfTrust\DTO\UserDescriptor;
use KDuma\BinaryTools\BinaryReader;
use KDuma\BinaryTools\BinaryString;
use KDuma\BinaryTools\BinaryWriter;

readonly class Certificate
{
    const string MAGIC = "\x08\x44\x53";

    public function __construct(
        public PublicKey                  $key,
        public string                     $description,
        /** @var UserDescriptor[] */
        public array                      $userDescriptors,
        public CertificateFlagsCollection $flags,
        /** @var Signature[] */
        public array                      $signatures
    )
    {
        if (empty($this->key->id->value)) {
            throw new \InvalidArgumentException('KeyId cannot be empty');
        }

        if ($this->key->id->size() !== 16) {
            throw new \InvalidArgumentException('KeyId must be 16 bytes');
        }

        if (empty($this->key->publicKey->value)) {
            throw new \InvalidArgumentException('Public key cannot be empty');
        }

        if ($this->key->publicKey->size() !== 32) {
            throw new \InvalidArgumentException('Public key must be 32 bytes');
        }

        if (empty($this->description)) {
            throw new \InvalidArgumentException('Description cannot be empty');
        }

        if (!mb_check_encoding($this->description, 'UTF-8')) {
            throw new \InvalidArgumentException('Description must be valid UTF-8');
        }

        if (array_any($this->userDescriptors, fn($element) => !$element instanceof UserDescriptor)) {
            throw new \InvalidArgumentException('All elements of $userDescriptors must be instances of UserDescriptor');
        }

        if (array_any($this->signatures, fn($element) => !$element instanceof Signature)) {
            throw new \InvalidArgumentException('All elements of $signatures must be instances of Signature');
        }
    }

    public function isSelfSigned(): bool
    {
        return $this->getSelfSignature() !== null;
    }

    public function getSignatureByKeyId(KeyId $keyId): ?Signature
    {
        return array_find($this->signatures, fn(Signature $signature) => $signature->keyId->equals($keyId));
    }

    public function getSelfSignature(): ?Signature
    {
        return $this->getSignatureByKeyId($this->key->id);
    }

    public function isRootCA(): bool
    {
        return $this->flags->hasRootCA() && $this->isSelfSigned();
    }

    public function toBinaryForSigning(): BinaryString
    {
        $writer = new BinaryWriter();

        $writer->writeBytes(BinaryString::fromString(self::MAGIC)); // Magic bytes encoding PUBK in base64
        $writer->writeByte(0x01); // Version

        $writer->writeBytes($this->key->id); // KeyId (16 bytes)
        $writer->writeBytes($this->key->publicKey); // Public Key (32 bytes for Ed25519)
        $writer->writeStringWithLength(BinaryString::fromString($this->description)); // Description
        $writer->writeByte(count($this->userDescriptors)); // User Descriptor Count
        foreach ($this->userDescriptors as $descriptor) {
            $writer->writeBytes($descriptor->toBinary());
        }
        $writer->writeUint16BE($this->flags->value); // Flags (2 bytes)

        return $writer->getBuffer();
    }

    public function toBinary(): BinaryString
    {
        $writer = new BinaryWriter();

        $writer->writeBytes($this->toBinaryForSigning());
        $writer->writeByte(count($this->signatures)); // Signature Count
        foreach ($this->signatures as $signature) {
            $writer->writeBytes($signature->toBinary(true));
        }

        return $writer->getBuffer();
    }

    public static function fromBinary(BinaryString $data): static
    {
        $reader = new BinaryReader($data);
        return self::fromBinaryReader($reader);
    }

    public static function fromBinaryReader(BinaryReader $reader): self
    {
        $magic = $reader->readBytes(3);
        if (!$magic->equals(BinaryString::fromString(self::MAGIC))) {
            throw new \InvalidArgumentException('Invalid magic bytes for Certificate');
        }

        try {
            $version = $reader->readByte();
            if ($version !== 1) {
                throw new \InvalidArgumentException('Unsupported Certificate version: 0x' . dechex($version));
            }
            $keyId = $reader->readBytes(16);
            $PubKey = $reader->readBytes(32);
            $Desc = $reader->readStringWithLength();
            $UserDescCount = $reader->readByte();
            $UserDescriptors = [];
            for ($i = 0; $i < $UserDescCount; $i++) {
                $UserDescriptors[] = UserDescriptor::fromBinaryReader($reader);
            }
            $Flags = CertificateFlagsCollection::fromInt($reader->readUint16BE());
            $SigCount = $reader->readByte();
            $Signatures = [];
            for ($i = 0; $i < $SigCount; $i++) {
                $Signatures[] = Signature::fromBinaryReader($reader, true);
            }
        } catch (\RuntimeException $e) {
            throw new \InvalidArgumentException('Failed to parse Certificate: ' . $e->getMessage());
        }

        if($reader->has_more_data && !$reader->peekBytes(3)->equals(BinaryString::fromString(self::MAGIC))) {
            throw new \InvalidArgumentException('Extra data found after parsing Certificate');
        }

        return new self(
            new PublicKey(KeyId::fromString($keyId->value), $PubKey),
            $Desc->toString(),
            $UserDescriptors,
            $Flags,
            $Signatures
        );
    }

    // @codeCoverageIgnoreStart
    public function with(
        ?PublicKey $key = null,
        ?string $description = null,
        ?array $userDescriptors = null,
        ?CertificateFlagsCollection $flags = null,
        ?array $signatures = null
    ): Certificate
    {
        return new self(
            $key ?? $this->key,
            $description ?? $this->description,
            $userDescriptors ?? $this->userDescriptors,
            $flags ?? $this->flags,
            $signatures ?? $this->signatures
        );
    }
    // @codeCoverageIgnoreEnd
}