<?php

namespace KDuma\CertificateChainOfTrust\Crypto;

use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use SodiumException;

class Ed25519
{
    public static function makeKeyPair(): PrivateKeyPair
    {
        $key_pair = sodium_crypto_sign_keypair();
        $public_key = new BinaryString(sodium_crypto_sign_publickey($key_pair));
        $secret_key = new BinaryString(sodium_crypto_sign_secretkey($key_pair));
        sodium_memzero($key_pair);

        return new PrivateKeyPair(
            KeyId::fromPublicKey($public_key),
            $public_key,
            $secret_key,
        );
    }
}