<?php

namespace KDuma\CertificateChainOfTrust\DTO;

use KDuma\CertificateChainOfTrust\Certificate;

readonly class ValidationResult
{
    /**
     * @param ValidationError[] $errors
     * @param ValidationWarning[] $warnings
     * @param Certificate[] $validatedChain
     * @param bool $isValid
     */
    public function __construct(
        public array $errors = [],
        public array $warnings = [],
        public array $validatedChain = [],
        public bool  $isValid = true
    ) {
    }

    public function getErrorMessages(): array
    {
        return array_map(fn ($error) => $error->getMessage(), $this->errors);
    }

    public function getWarningMessages(): array
    {
        return array_map(fn ($warning) => $warning->getMessage(), $this->warnings);
    }
}
