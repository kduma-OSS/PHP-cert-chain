<?php

namespace KDuma\CertificateChainOfTrust\DTO;


use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\Crypto\PrivateKeyPair;
use KDuma\CertificateChainOfTrust\Crypto\PublicKey;
use KDuma\CertificateChainOfTrust\Utils\BinaryReader;
use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use KDuma\CertificateChainOfTrust\Utils\BinaryWriter;

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

    public function toBinary(): BinaryString
    {
        $writer = new BinaryWriter();
        $writer->writeBytesWithLength($this->keyId);
        $writer->writeBytesWithLength($this->signature);

        return $writer->getBuffer();
    }

    public static function fromBinaryReader(BinaryReader $reader): self
    {
        $keyId = $reader->readBytesWithLength();
        try {
            $signature = $reader->readBytesWithLength();
        } catch (\RuntimeException $e) {
            $reader->position -= $keyId->size() + 1; // rewind to before reading keyId
            throw $e;
        }

        return new self(new KeyId($keyId->value), $signature);
    }

    public static function fromBinary(BinaryString $binary): self
    {
        $reader = new BinaryReader($binary);
        return self::fromBinaryReader($reader);
    }

    public static function make(BinaryString $data, PrivateKeyPair $keyPair): Signature
    {
        $signature = new BinaryString(sodium_crypto_sign_detached($data->value, $keyPair->privateKey->value));

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