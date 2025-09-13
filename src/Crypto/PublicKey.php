<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\Crypto;

use KDuma\BinaryTools\BinaryReader;
use KDuma\BinaryTools\BinaryString;
use KDuma\BinaryTools\BinaryWriter;

readonly class PublicKey
{
    public const string MAGIC = "\x3e\xe6\xca";

    public function __construct(
        public KeyId $id,
        public BinaryString $publicKey,
    ) {
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

        $writer->writeBytes(BinaryString::fromString(self::MAGIC)); // Magic bytes encoding PUBK in base64

        $writer->writeBytesWithLength($this->id);
        $writer->writeBytesWithLength($this->publicKey, true);

        return $writer->getBuffer();
    }

    public static function fromBinary(BinaryString $data): static
    {
        $reader = new BinaryReader($data);
        $magic = $reader->readBytes(3);
        if (!$magic->equals(BinaryString::fromString(self::MAGIC))) {
            throw new \InvalidArgumentException('Invalid magic bytes for PublicKey');
        }

        try {
            $id = KeyId::fromString($reader->readBytesWithLength()->value);
            $publicKey = $reader->readBytesWithLength(true);
        } catch (\RuntimeException $e) {
            throw new \InvalidArgumentException('Failed to parse PublicKey: ' . $e->getMessage());
        }

        if ($reader->has_more_data) {
            throw new \InvalidArgumentException('Extra data found after parsing PublicKey');
        }

        return new self(
            $id,
            $publicKey,
        );
    }
}
