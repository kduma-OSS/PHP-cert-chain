<?php

namespace KDuma\CertificateChainOfTrust\Crypto;

use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use KDuma\CertificateChainOfTrust\Utils\BinaryWriter;

readonly class PublicKey
{
    public function __construct(
        public KeyId $id,
        public BinaryString $publicKey,
    )
    {
    }

    public function isKeyIdValid(): bool
    {
        return KeyId::fromPublicKey($this->publicKey)->equals($this->id);
    }

    public function toArray(): array
    {
        return [
            'id' => bin2hex($this->id->toString()),
            'publicKey' => bin2hex($this->publicKey->toString()),
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            KeyId::fromHex($data['id']),
            BinaryString::fromHex($data['publicKey']),
        );
    }

    public function toBinary(): BinaryString
    {
        $writer = new BinaryWriter();

        $writer->writeBytes(new BinaryString("\x3e\xe6\xca")); // Magic bytes encoding PUBK in base64

        $writer->writeBytesWithLength($this->id);
        $writer->writeBytesWithLength($this->publicKey, true);

        return new BinaryString($writer->getBinary());
    }
}