<?php

namespace KDuma\CertificateChainOfTrust;

use KDuma\BinaryTools\BinaryReader;
use KDuma\BinaryTools\BinaryString;
use KDuma\BinaryTools\BinaryWriter;
use Override;

readonly class TrustStore extends CertificatesContainer
{
    #[Override]
    protected function validateAddedCertificate(Certificate $certificate): void
    {
        if (!$certificate->isRootCA()) {
            throw new \InvalidArgumentException('Only self-signed root CA certificates can be added to trust store');
        }

        if(count(array_filter($this->certificates, fn($c) => $c->key->id->equals($certificate->key->id))) !== 1) {
            throw new \InvalidArgumentException('Certificates in trust store must have unique KeyIds');
        }
    }

    #[Override]
    protected static function getMagicBytes(): string
    {
        return "\x4e\xbb\xac\xb5\xe7\x4a";
    }
}