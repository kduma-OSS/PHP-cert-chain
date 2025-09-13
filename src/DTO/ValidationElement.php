<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust\DTO;

use KDuma\CertificateChainOfTrust\Certificate;

abstract readonly class ValidationElement
{
    public function __construct(
        public string $message,
        public ?Certificate $certificate = null,
        public ?string $context = null
    ) {
    }

    public function getMessage(): string
    {
        $msg = $this->message;

        if ($this->certificate) {
            $msg .= " (Certificate: " . $this->certificate->key->id->toHex() . ")";
        }

        if ($this->context) {
            $msg .= " [" . $this->context . "]";
        }

        return $msg;
    }
}
