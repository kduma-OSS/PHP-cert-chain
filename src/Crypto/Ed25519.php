<?php

namespace KDuma\CertificateChainOfTrust\Crypto;

use KDuma\BinaryTools\BinaryString;

class Ed25519
{
    public static function makeKeyPair(): PrivateKeyPair
    {
        $key_pair = sodium_crypto_sign_keypair();
        $public_key = BinaryString::fromString(sodium_crypto_sign_publickey($key_pair));
        $secret_key = BinaryString::fromString(sodium_crypto_sign_secretkey($key_pair));
        sodium_memzero($key_pair);

        return new PrivateKeyPair(
            KeyId::fromPublicKey($public_key),
            $public_key,
            $secret_key,
        );
    }
}
