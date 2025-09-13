<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\DTO;

use KDuma\BinaryTools\BinaryReader;
use KDuma\BinaryTools\BinaryString;
use KDuma\BinaryTools\BinaryWriter;
use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PrivateKeyPair;
use KDuma\CertificateChainOfTrust\Crypto\PublicKey;

readonly class Signature
{
    public function __construct(
        public KeyId $keyId,
        public BinaryString $signature
    ) {
        if (!$keyId->value) {
            throw new \InvalidArgumentException('Signer KeyId cannot be empty');
        }

        if (!$signature->value) {
            throw new \InvalidArgumentException('Signature cannot be empty');
        }
    }

    public function equals(Signature $other): bool
    {
        return $this->keyId->equals($other->keyId) && $this->signature->equals($other->signature);
    }

    public function toBinary(bool $fixed_length = false): BinaryString
    {
        $writer = new BinaryWriter();
        if ($fixed_length) {
            if ($this->keyId->size() !== 16) {
                throw new \InvalidArgumentException('KeyId must be 16 bytes for fixed length encoding');
            }
            if ($this->signature->size() !== 64) {
                throw new \InvalidArgumentException('Signature must be 64 bytes for fixed length encoding');
            }
            $writer->writeBytes($this->keyId);
            $writer->writeBytes($this->signature);
            return $writer->getBuffer();
        }

        $writer->writeBytesWithLength($this->keyId);
        $writer->writeBytesWithLength($this->signature);

        return $writer->getBuffer();
    }

    public static function fromBinaryReader(BinaryReader $reader, bool $fixed_length = false): self
    {
        $initialPosition = $reader->position;

        try {
            if ($fixed_length) {
                $keyId = $reader->readBytes(16);
                $signature = $reader->readBytes(64);
            } else {
                $keyId = $reader->readBytesWithLength();
                $signature = $reader->readBytesWithLength();
            }
        } catch (\RuntimeException $e) {
            $reader->position = $initialPosition; // rewind to before reading keyId
            throw $e;
        }

        return new self(KeyId::fromString($keyId->value), $signature);
    }

    public static function fromBinary(BinaryString $binary, bool $fixed_length = false): self
    {
        $reader = new BinaryReader($binary);
        return self::fromBinaryReader($reader, $fixed_length);
    }

    public static function make(BinaryString $data, PrivateKeyPair $keyPair): Signature
    {
        $signature = BinaryString::fromString(sodium_crypto_sign_detached($data->value, $keyPair->privateKey->value));

        return new self($keyPair->id, $signature);
    }

    public function validate(BinaryString $data, PublicKey $key): bool
    {
        if (!$this->keyId->equals($key->id)) {
            throw new \InvalidArgumentException('KeyId does not match the provided key');
        }

        return sodium_crypto_sign_verify_detached($this->signature->value, $data->value, $key->publicKey->value);
    }
}
