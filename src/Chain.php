<?php

namespace KDuma\CertificateChainOfTrust;

use KDuma\CertificateChainOfTrust\DTO\ValidationError;
use KDuma\CertificateChainOfTrust\DTO\ValidationResult;
use KDuma\CertificateChainOfTrust\DTO\ValidationWarning;
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

    public function validate(TrustStore $store): ValidationResult
    {
        $errors = [];
        $warnings = [];
        $validatedChain = [];
        
        // Initial validation - check if chain has certificates
        $certificate = $this->getFirstCertificate();
        if ($certificate === null) {
            $errors[] = new ValidationError('No certificates in chain to validate');
            return new ValidationResult($errors, $warnings, $validatedChain, false);
        }
        
        // Build all possible paths from the first certificate to root CAs
        $paths = $this->buildPaths($certificate);
        
        if (empty($paths)) {
            $errors[] = new ValidationError('No complete certification path found', $certificate, 'path building');
            return new ValidationResult($errors, $warnings, $validatedChain, false);
        }
        
        // Validate each path to find at least one valid path
        $validPath = null;
        $pathErrors = [];
        
        foreach ($paths as $path) {
            $pathValidationResult = $this->validatePath($path, $store);
            
            if ($pathValidationResult['isValid']) {
                $validPath = $path;
                if (!empty($pathValidationResult['warnings'])) {
                    // @codeCoverageIgnoreStart
                    $warnings = array_merge($warnings, $pathValidationResult['warnings']);
                    // @codeCoverageIgnoreEnd
                }
                break; // Found valid path, can stop here
            } else {
                $pathErrors[] = $pathValidationResult['errors'];
            }
        }
        
        // If no valid path found, collect all errors
        if ($validPath === null) {
            $errors[] = new ValidationError('No valid certification path found', $certificate, 'chain validation');
            foreach ($pathErrors as $pathErrorList) {
                $errors = array_merge($errors, $pathErrorList);
            }
            return new ValidationResult($errors, $warnings, $validatedChain, false);
        }
        
        // Add warning if multiple paths exist
        if (count($paths) > 1) {
            // @codeCoverageIgnoreStart
            $warnings[] = new ValidationWarning('Multiple certification paths found', $certificate, 'path analysis');
            // @codeCoverageIgnoreEnd
        }
        
        return new ValidationResult($errors, $warnings, $validPath, true);
    }
    
    /**
     * Validate a single certification path
     * 
     * @param Certificate[] $path Path from leaf to root certificate
     * @param TrustStore $store Trust store containing trusted root CAs
     * @return array{isValid: bool, errors: ValidationError[], warnings: ValidationWarning[]}
     */
    private function validatePath(array $path, TrustStore $store): array
    {
        $errors = [];
        $warnings = [];
        
        if (empty($path)) {
            // @codeCoverageIgnoreStart
            $errors[] = new ValidationError('Empty certification path provided');
            return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
            // @codeCoverageIgnoreEnd
        }
        
        // Verify the last certificate in path is a root CA
        $rootCert = end($path);
        if (!$rootCert->isRootCA()) {
            // @codeCoverageIgnoreStart
            $errors[] = new ValidationError('Path does not end with a root CA certificate', $rootCert, 'root CA validation');
            return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
            // @codeCoverageIgnoreEnd
        }
        
        // Verify the root CA is in the trust store
        if ($store->getById($rootCert->key->id) === null) {
            $errors[] = new ValidationError('Root CA is not in the trust store', $rootCert, 'trust store validation');
            return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
        }
        
        // Verify signature chain from leaf to root
        for ($i = 0; $i < count($path) - 1; $i++) {
            $currentCert = $path[$i];
            $signerCert = $path[$i + 1];
            
            // Get the signature on current certificate made by signer
            $signature = $currentCert->getSignatureByKeyId($signerCert->key->id);
            if ($signature === null) {
                // @codeCoverageIgnoreStart
                $errors[] = new ValidationError("Certificate is not signed by the next certificate in path", $currentCert, "signature verification at position $i");
                return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
                // @codeCoverageIgnoreEnd
            }
            
            // Verify the signature
            try {
                $dataToSign = $currentCert->toBinaryForSigning();
                $isSignatureValid = $signature->validate($dataToSign, $signerCert->key);
                
                if (!$isSignatureValid) {
                    // @codeCoverageIgnoreStart
                    $errors[] = new ValidationError("Invalid signature on certificate", $currentCert, "cryptographic verification at position $i");
                    return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
                    // @codeCoverageIgnoreEnd
                }
            // @codeCoverageIgnoreStart
            } catch (\Exception $e) {
                $errors[] = new ValidationError("Signature verification failed: " . $e->getMessage(), $currentCert, "signature validation at position $i");
                return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
            }
            // @codeCoverageIgnoreEnd
        }
        
        // Verify root certificate's self-signature if it exists
        $rootSelfSignature = $rootCert->getSelfSignature();
        if ($rootSelfSignature !== null) {
            try {
                $dataToSign = $rootCert->toBinaryForSigning();
                $isSignatureValid = $rootSelfSignature->validate($dataToSign, $rootCert->key);
                
                if (!$isSignatureValid) {
                    // @codeCoverageIgnoreStart
                    $errors[] = new ValidationError("Invalid self-signature on root CA certificate", $rootCert, "root CA self-signature verification");
                    return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
                    // @codeCoverageIgnoreEnd
                }
            // @codeCoverageIgnoreStart
            } catch (\Exception $e) {
                $errors[] = new ValidationError("Root CA self-signature verification failed: " . $e->getMessage(), $rootCert, "root CA signature validation");
                return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
            }
            // @codeCoverageIgnoreEnd
        }
        
        return ['isValid' => true, 'errors' => $errors, 'warnings' => $warnings];
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