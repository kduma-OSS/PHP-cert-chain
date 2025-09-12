<?php

namespace KDuma\CertificateChainOfTrust\Crypto;


use KDuma\CertificateChainOfTrust\Utils\BinaryString;

readonly class KeyId extends BinaryString
{
    public static function fromPublicKey(BinaryString $public_key): self
    {
        $hash = hash('sha256', $public_key->toString(), true);
        $hash = substr($hash, 0, 16);

        return new self($hash);
    }
}