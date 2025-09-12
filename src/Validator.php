<?php

namespace KDuma\CertificateChainOfTrust;

use KDuma\CertificateChainOfTrust\DTO\ValidationError;
use KDuma\CertificateChainOfTrust\DTO\ValidationResult;
use KDuma\CertificateChainOfTrust\DTO\ValidationWarning;

class Validator
{
    public static function validateChain(Chain $chain, TrustStore $store): ValidationResult
    {
        $errors = [];
        $warnings = [];
        $validatedChain = [];
        
        // Initial validation - check if chain has certificates
        $certificate = $chain->getFirstCertificate();
        if ($certificate === null) {
            $errors[] = new ValidationError('No certificates in chain to validate');
            return new ValidationResult($errors, $warnings, $validatedChain, false);
        }
        
        // Build all possible paths from the first certificate to root CAs
        $paths = $chain->buildPaths($certificate);
        
        if (empty($paths)) {
            $errors[] = new ValidationError('No complete certification path found', $certificate, 'path building');
            return new ValidationResult($errors, $warnings, $validatedChain, false);
        }
        
        // Validate each path to find at least one valid path
        $validPath = null;
        $pathErrors = [];
        
        foreach ($paths as $path) {
            $pathValidationResult = self::validatePath($path, $store);
            
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
    private static function validatePath(array $path, TrustStore $store): array
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
}