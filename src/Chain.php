<?php

namespace KDuma\CertificateChainOfTrust;

use Override;

readonly class Chain extends CertificatesContainer
{
    #[Override]
    protected function validateAddedCertificate(Certificate $certificate): void
    {
        // Dont need to validate anything specific for Chain
    }

    #[Override]
    protected static function getMagicBytes(): string
    {
        return ''; // No specific magic bytes for Chain
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
        $leaf ??= $this->getFirstCertificate();
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