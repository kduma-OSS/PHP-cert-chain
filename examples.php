<?php

use KDuma\CertificateChainOfTrust\Certificate;
use KDuma\CertificateChainOfTrust\Crypto\PrivateKeyPair;
use KDuma\CertificateChainOfTrust\DTO\CertificateFlag;
use KDuma\CertificateChainOfTrust\DTO\CertificateFlagsCollection;
use KDuma\CertificateChainOfTrust\DTO\DescriptorType;
use KDuma\CertificateChainOfTrust\DTO\Signature;
use KDuma\CertificateChainOfTrust\DTO\UserDescriptor;
use KDuma\BinaryTools\BinaryString;

require __DIR__ . '/vendor/autoload.php';

$keys = [
    '118eb5' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEBGOtafGzJ3Y/fCTHjAFgpAAIGuO0NhRV3KFRGUnHWAX3e6r9bkVzdvHgm5xOk6uuFECAEC9PIBmk/h0zA19SYlXU4mRdHjts2VHFWmrgaYGSrLGk2uO0NhRV3KFRGUnHWAX3e6r9bkVzdvHgm5xOk6uuFEC')),
    '43f1cc' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEEPxzBP7KfedSZLFubexQ7AAIK9BhyF5hbcvSpCBp0oLeuASZ/5CmzFlVnzbhjf0C1MZAECHE1GTDuqap0bVslnTtnvavMWVB/hrEQjPB+7/M6UWra9BhyF5hbcvSpCBp0oLeuASZ/5CmzFlVnzbhjf0C1MZ')),

    '48bfea' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEEi/6ipM2vpTO2H2Z2XKU5wAINBftS5c3toShrAKTsZoVfZz2WishU0K4lTF0yQv10FmAEBM4rEwhmGGEtPCSixVydLgjfkX44IyqcxT05S+GV+zrNBftS5c3toShrAKTsZoVfZz2WishU0K4lTF0yQv10Fm')),
    '51732c' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEFFzLKCvOgftgrjMZJ6ayzUAIO/aR733gY6qlOiXReUHWXBkbRkaG4P/L9qE6JdDKTJOAEA5xWFvMyKd5imH2HhTHLE++HbIpxD70wW5kbdrctDsGO/aR733gY6qlOiXReUHWXBkbRkaG4P/L9qE6JdDKTJO')),
    '56e10d' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEFbhDamMUdpuhUYC8IOsr58AIOATX5p457FQ50vFKjjz6SzG5/ltFj1DDonb0/JHXwFUAEB6PjLguV8NzvZeittYfPaPgs9h4DKvc5V1OR4Qi9AviuATX5p457FQ50vFKjjz6SzG5/ltFj1DDonb0/JHXwFU')),

    '635af3' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEGNa8+QYDHytxsAsITW8LI8AIASHcCTH6CsSDzIfVDsauBgrPq8S4me0dWEtu6gxhlkXAEAsa8KC7gIwubTdbiQU19S94mJicIwqrdZY+A5EeJGR/gSHcCTH6CsSDzIfVDsauBgrPq8S4me0dWEtu6gxhlkX')),
    '6c2222' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEGwiImb8FDDMLwan9RHcof4AIAtB/h6SBYptybb//CP+cF9w3hxJqgNuWNQ+nkJtGFeGAECqX0xUbiFU7ZF6E7cSSIrkTssM8H8FCgZf3Hpi4Z9bIwtB/h6SBYptybb//CP+cF9w3hxJqgNuWNQ+nkJtGFeG')),
    '8e89a3' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEI6Jo65fqQvQsCdsfHcyGCAAIBw+blUs3GKCgz8ZLyhGjOTNooW+c0Z87mu0WCd67CMDAEA7j4l+roRcHPObiGHjpZsQSWssN2/aKYp9lojEIT6H5Bw+blUs3GKCgz8ZLyhGjOTNooW+c0Z87mu0WCd67CMD')),

    '920e49' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEJIOSY97t8JzHJEcmgsMIm4AIPYQXNdxox48tEh9FqNl9+Tzd1x4ZneT8i+5N8/wd2dzAEBfaJdOIk10096ZuxpS9W1Eu6LWpqCKrcZQ/hwH2VA/JfYQXNdxox48tEh9FqNl9+Tzd1x4ZneT8i+5N8/wd2dz')),
    '93a308' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEJOjCGltNmKYrBt6FOesK6sAIFgxcqbPeRXarWHGfA3tZN8UJToUYR2R1pzsWZlAUgwrAECX0bDECkI88/uawKaaX4ckG4biRmc6BPuazfa6WdQ70lgxcqbPeRXarWHGfA3tZN8UJToUYR2R1pzsWZlAUgwr')),
    '94dfc9' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEJTfyb3DVde+rOgjAU/gOzsAIPiSsWJkBHmGCAoGTAQVSJQwZD0zNgZjYAJ0aQGRYkWKAEBHsunSTxWh2ikFqX83vDMVGzrAUxK9BJo0K+PPeIXl7PiSsWJkBHmGCAoGTAQVSJQwZD0zNgZjYAJ0aQGRYkWK')),
    '9fdf19' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEJ/fGbeWCjU9EC75Gb/P+y4AIFsKfzwcwA95jde3K/Rmg9lnwp6JMtCthmCgmzsMoT0uAEDkkE0nKqb7++N8+KcB8JRJ18y2pU2J+2vIrLjKHCCAIFsKfzwcwA95jde3K/Rmg9lnwp6JMtCthmCgmzsMoT0u')),
    'afa15e' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEK+hXt3fbEddDQlNz35RGqoAIMClhUHtBQwhEcnQd2PwwTWJASMwTjRqF6s8wJeGyE0rAEBcSrh4nsQH7APUrxpdT8ovuEy86s6Qr+40Z4cyZirpCsClhUHtBQwhEcnQd2PwwTWJASMwTjRqF6s8wJeGyE0r')),
    'b9e804' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKELnoBLkA44dm0LMP8oxDIAUAIE1ZGD8D7C9Hf5BfY5Inj2bfVAtjAmeFgsfqzleS2QqVAEDaEH/WqAgYgT2gpDwJtzboB4NKmuhGR4OW1+aj2v6W9U1ZGD8D7C9Hf5BfY5Inj2bfVAtjAmeFgsfqzleS2QqV')),
    'd44998' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKENRJmEWYpi+0nfodtYyeUeMAINxMD0A1KjEBYTCPB4tkL4sL3BymX81dVx/K82wt9tUgAEAacPvt0A3hKonaDIlmjZip4NrWmhAcstEC5uEIlam5NtxMD0A1KjEBYTCPB4tkL4sL3BymX81dVx/K82wt9tUg')),
    'f2d32c' => PrivateKeyPair::fromBinary(BinaryString::fromBase64('PrivateKEPLTLOeYRSshhoCk+EtR4ngAIDrJ05EZnCtmnvrriKr8FrH1ynAH9qvyUYB76cTRQePWAEC7o7zpnCAaukvopRpN7hK81VWHlf7hDLuEiGgdKZ8dYjrJ05EZnCtmnvrriKr8FrH1ynAH9qvyUYB76cTRQePW')),
];

$root_ca_1 = new Certificate(
    key: $keys['118eb5'],
    description: 'My Root CA 1',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'root-ca-1.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::ROOT_CA,
        CertificateFlag::CA,
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::DOCUMENT_SIGNER,
        CertificateFlag::TEMPLATE_SIGNER
    ]),
    signatures: []
);
$root_ca_1 = $root_ca_1->with(signatures: [Signature::make($root_ca_1->toBinaryForSigning(), $keys['118eb5'])]);

$root_ca_2 = new Certificate(
    key: $keys['43f1cc'],
    description: 'My Root CA 2',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'root-ca-2.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::ROOT_CA,
        CertificateFlag::CA,
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::DOCUMENT_SIGNER,
    ]),
    signatures: []
);
$root_ca_2 = $root_ca_2->with(signatures: [Signature::make($root_ca_2->toBinaryForSigning(), $keys['43f1cc'])]);

$intermediate_ca_1 = new Certificate(
    key: $keys['48bfea'],
    description: 'My Intermediate CA 1 (on Root CA 1)',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'intermediate-ca-1.root-ca-1.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::DOCUMENT_SIGNER,
        CertificateFlag::TEMPLATE_SIGNER
    ]),
    signatures: []
);
$intermediate_ca_1 = $intermediate_ca_1->with(signatures: [Signature::make($intermediate_ca_1->toBinaryForSigning(), $keys['118eb5'])]);

$intermediate_ca_2 = new Certificate(
    key: $keys['51732c'],
    description: 'My Intermediate CA 2 (on Root CA 1)',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'intermediate-ca-2.root-ca-1.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::DOCUMENT_SIGNER,
        CertificateFlag::TEMPLATE_SIGNER
    ]),
    signatures: []
);
$intermediate_ca_2 = $intermediate_ca_2->with(signatures: [Signature::make($intermediate_ca_2->toBinaryForSigning(), $keys['118eb5'])]);

$intermediate_ca_3 = new Certificate(
    key: $keys['56e10d'],
    description: 'My Intermediate CA 3 (on Root CA 2)',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'intermediate-ca-3.root-ca-2.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::DOCUMENT_SIGNER,
        CertificateFlag::TEMPLATE_SIGNER
    ]),
    signatures: []
);
$intermediate_ca_3 = $intermediate_ca_3->with(signatures: [Signature::make($intermediate_ca_3->toBinaryForSigning(), $keys['43f1cc'])]);

$ca_1 = new Certificate(
    key: $keys['635af3'],
    description: 'My CA 1 (on Root CA 1)',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'ca-1.root-ca-1.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::DOCUMENT_SIGNER,
        CertificateFlag::TEMPLATE_SIGNER
    ]),
    signatures: []
);
$ca_1 = $ca_1->with(signatures: [Signature::make($ca_1->toBinaryForSigning(), $keys['118eb5'])]);

$ca_2 = new Certificate(
    key: $keys['6c2222'],
    description: 'My CA 2 (on Intermediate CA 1)',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'ca-2.intermediate-ca-1.root-ca-1.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::CA,
        CertificateFlag::DOCUMENT_SIGNER,
        CertificateFlag::TEMPLATE_SIGNER
    ]),
    signatures: []
);
$ca_2 = $ca_2->with(signatures: [Signature::make($ca_2->toBinaryForSigning(), $keys['48bfea'])]);

$ca_3 = new Certificate(
    key: $keys['8e89a3'],
    description: 'My CA 3 (on Root CA 2)',
    userDescriptors: [
        new UserDescriptor(DescriptorType::DOMAIN, 'ca-3.root-ca-2.example.com'),
    ],
    flags: CertificateFlagsCollection::fromList([
        CertificateFlag::INTERMEDIATE_CA,
        CertificateFlag::DOCUMENT_SIGNER,
        CertificateFlag::TEMPLATE_SIGNER
    ]),
    signatures: []
);
$ca_3 = $ca_3->with(signatures: [Signature::make($ca_3->toBinaryForSigning(), $keys['118eb5'])]);



$certificates = [
    'root-ca-1.example.com' => $root_ca_1,
    'root-ca-2.example.com' => $root_ca_2,

    'intermediate-ca-1.root-ca-1.example.com' => $intermediate_ca_1,
    'intermediate-ca-2.root-ca-1.example.com' => $intermediate_ca_2,
    'intermediate-ca-3.root-ca-2.example.com' => $intermediate_ca_3,

    'ca-1.root-ca-1.example.com' => $ca_1,
    'ca-2.intermediate-ca-1.root-ca-1.example.com' => $ca_2,
    'ca-3.root-ca-2.example.com' => $ca_3,
];


var_dump($root_ca_1);
