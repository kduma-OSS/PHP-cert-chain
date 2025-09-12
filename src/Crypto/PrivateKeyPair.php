<?php

namespace KDuma\CertificateChainOfTrust\Crypto;

use KDuma\CertificateChainOfTrust\Utils\BinaryReader;
use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use KDuma\CertificateChainOfTrust\Utils\BinaryWriter;

readonly class PrivateKeyPair extends PublicKey
{
    public function __construct(
        KeyId $id,
        BinaryString $publicKey,
        public BinaryString $privateKey,
    )
    {
        parent::__construct($id, $publicKey);
    }


    public function toArray(): array
    {
        return [
            'id' => bin2hex($this->id->toString()),
            'publicKey' => bin2hex($this->publicKey->toString()),
            'privateKey' => bin2hex($this->privateKey->toString()),
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            KeyId::fromHex($data['id']),
            BinaryString::fromHex($data['publicKey']),
            BinaryString::fromHex($data['privateKey']),
        );
    }

    public function toBinary(): BinaryString
    {
        $writer = new BinaryWriter();

        $writer->writeBytes(new BinaryString("\x3e\xb8\xaf\x6a\xd7\x8a"));

        $writer->writeBytesWithLength($this->id);
        $writer->writeBytesWithLength($this->publicKey, true);
        $writer->writeBytesWithLength($this->privateKey, true);

        return $writer->getBuffer();
    }

    public static function fromBinary(BinaryString $data): static
    {
        $reader = new BinaryReader($data);
        $magic = $reader->readBytes(6);
        if (!$magic->equals(new BinaryString("\x3e\xb8\xaf\x6a\xd7\x8a"))) {
            throw new \InvalidArgumentException('Invalid magic bytes for PrivateKey');
        }

        try {
            $id = new KeyId($reader->readBytesWithLength()->value);
            $publicKey = $reader->readBytesWithLength(true);
            $privateKey = $reader->readBytesWithLength(true);
        } catch (\RuntimeException $e) {
            throw new \InvalidArgumentException('Failed to parse PrivateKey: ' . $e->getMessage());
        }

        if($reader->has_more_data) {
            throw new \InvalidArgumentException('Extra data found after parsing PrivateKey');
        }

        return new self(
            $id,
            $publicKey,
            $privateKey
        );
    }
}