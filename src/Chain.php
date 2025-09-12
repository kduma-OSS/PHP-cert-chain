<?php

namespace KDuma\CertificateChainOfTrust;

use KDuma\CertificateChainOfTrust\Utils\BinaryReader;
use KDuma\CertificateChainOfTrust\Utils\BinaryString;
use KDuma\CertificateChainOfTrust\Utils\BinaryWriter;

readonly class Chain
{
    public function __construct(
        /** @var Certificate[] */
        public array $certificates = [],
    )
    {
        if (array_any($this->certificates, fn($certificate) => !$certificate instanceof Certificate)) {
            throw new \InvalidArgumentException('All elements of $certificates must be instances of Certificate');
        }
    }

    public function getCertificate(): ?Certificate
    {
        return $this->certificates[0] ?? null;
    }

    public static function fromBinary(BinaryString $data): static
    {
        $reader = new BinaryReader($data);
        return self::fromBinaryReader($reader);
    }

    public static function fromBinaryReader(BinaryReader $reader): self
    {
        $certificates = [];
        while ($reader->has_more_data) {
            $certificates[] = Certificate::fromBinaryReader($reader);
        }

        return new self($certificates);
    }

    public function toBinary(): BinaryString
    {
        $writer = new BinaryWriter();

        foreach ($this->certificates as $certificate) {
            $writer->writeBytes($certificate->toBinary());
        }

        return $writer->getBuffer();
    }

    /**
     * @return Certificate[]
     */
    public function getLeafCertificates(): array {
        $leafCertificates = [];
        
        foreach ($this->certificates as $certificate) {
            // A leaf certificate is one that doesn't sign any other certificate in the chain
            $isLeaf = true;
            
            foreach ($this->certificates as $otherCert) {
                if ($certificate === $otherCert) {
                    continue;
                }
                
                // Check if this certificate signed the other certificate
                if ($otherCert->getSignatureByKeyId($certificate->key->id) !== null) {
                    $isLeaf = false;
                    break;
                }
            }
            
            if ($isLeaf) {
                $leafCertificates[] = $certificate;
            }
        }
        
        return $leafCertificates;
    }

    /**
     * @return Certificate[]
     */
    public function getRootCertificates(): array {
        return array_values(array_filter($this->certificates, fn(Certificate $certificate) => $certificate->isRootCA()));
    }

    /**
     * Build certificate paths from leaf to root
     *
     * @param Certificate $leaf Starting certificate
     * @return Certificate[][] Array of possible paths
     */
    public function buildPaths(?Certificate $leaf = null): array
    {
        $leaf ??= $this->getCertificate();
        if ($leaf === null) {
            return [];
        }

        $paths = [];
        $this->buildPathsRecursive($leaf, [$leaf], $paths, []);
        return $paths;
    }
    
    /**
     * Recursive helper method for building certificate paths
     *
     * @param Certificate $current Current certificate in the path
     * @param Certificate[] $currentPath Current path being built
     * @param Certificate[][] &$paths Reference to all found paths
     * @param Certificate[] $visited Certificates already visited to prevent cycles
     */
    private function buildPathsRecursive(Certificate $current, array $currentPath, array &$paths, array $visited): void
    {
        // Prevent infinite loops by tracking visited certificates
        // @codeCoverageIgnoreStart
        if (in_array($current, $visited, true)) {
            return;
        }
        // @codeCoverageIgnoreEnd
        
        $visited[] = $current;
        
        // If current certificate is a root CA, we've found a complete path
        if ($current->isRootCA()) {
            $paths[] = $currentPath;
            return;
        }
        
        // Find all certificates that could have signed the current certificate
        $signers = [];
        foreach ($this->certificates as $potential_signer) {
            if ($potential_signer === $current) {
                continue;
            }
            
            // Check if this certificate signed the current certificate
            if ($current->getSignatureByKeyId($potential_signer->key->id) !== null) {
                $signers[] = $potential_signer;
            }
        }
        
        // If no signers found, this is a dead end
        if (empty($signers)) {
            return;
        }
        
        // Recursively build paths for each signer
        foreach ($signers as $signer) {
            $newPath = $currentPath;
            $newPath[] = $signer;
            $this->buildPathsRecursive($signer, $newPath, $paths, $visited);
        }
    }
}