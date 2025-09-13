<?php declare(strict_types=1);

namespace KDuma\CertificateChainOfTrust;

use KDuma\CertificateChainOfTrust\Crypto\KeyId;
use KDuma\CertificateChainOfTrust\DTO\ValidationError;
use KDuma\CertificateChainOfTrust\DTO\ValidationResult;
use KDuma\CertificateChainOfTrust\DTO\ValidationWarning;

/**
 * Validator enforces the policy defined in SPECIFICATION.md.
 * Key sections referenced throughout this file:
 * - Roles and combinations
 * - Signing rules matrix
 * - End‑Entity Inheritance Matrix
 * - Chain validation algorithm
 * - Ed25519 details
 */
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

        // Ensure every certificate in the chain has at least one signature
        // SPECIFICATION.md: Certificates must contain at least one signature entry (structural validity)
        foreach ($chain->certificates as $cert) {
            if (count($cert->signatures) === 0) {
                $errors[] = new ValidationError('Certificate has no signatures', $cert, 'signature presence');
                return new ValidationResult($errors, $warnings, $validatedChain, false);
            }
        }

        // Build all possible paths from the first certificate to root CAs
        // SPECIFICATION.md: Chain validation algorithm — build path(s) from leaf to trusted root
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
        // SPECIFICATION.md: Chain validation algorithm — multiple possible paths may exist
        if (count($paths) > 1) {
            $warnings[] = new ValidationWarning('Multiple certification paths found', $certificate, 'path analysis');
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
            $errors[] = new ValidationError('Empty certification path provided');
            return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
        }

        // Verify that each certificate's embedded KeyId matches its public key
        // SPECIFICATION.md: Ed25519 details — KeyId = first 16 bytes of SHA-256 over 32-byte public key
        foreach ($path as $certificate) {
            $computedKeyId = KeyId::fromPublicKey($certificate->key->publicKey);
            if (!$computedKeyId->equals($certificate->key->id)) {
                $errors[] = new ValidationError('KeyId does not match public key', $certificate, 'key id validation');
                return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
            }
        }

        // Verify the last certificate in path is a root CA
        $rootCert = end($path);
        if (!$rootCert->isRootCA()) {
            $errors[] = new ValidationError('Path does not end with a root CA certificate', $rootCert, 'root CA validation');
            return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
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
                $errors[] = new ValidationError("Certificate is not signed by the next certificate in path", $currentCert, "signature verification at position $i");
                return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
            }

            // Verify the signature
            try {
                $dataToSign = $currentCert->toBinaryForSigning();
                $isSignatureValid = $signature->validate($dataToSign, $signerCert->key);

                if (!$isSignatureValid) {
                    $errors[] = new ValidationError("Invalid signature on certificate", $currentCert, "cryptographic verification at position $i");
                    return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
                }
                // @codeCoverageIgnoreStart
            } catch (\Exception $e) {
                $errors[] = new ValidationError("Signature verification failed: " . $e->getMessage(), $currentCert, "signature validation at position $i");
                return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
            }
            // @codeCoverageIgnoreEnd

            // Validate certificate authority rules
            $authorityValidation = self::validateCertificateAuthority($currentCert, $signerCert);
            if (!$authorityValidation['isValid']) {
                $errors = array_merge($errors, $authorityValidation['errors']);
                return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
            }

            // Validate end-entity flag inheritance
            $inheritanceValidation = self::validateEndEntityFlagInheritance($currentCert, $signerCert);
            if (!$inheritanceValidation['isValid']) {
                $errors = array_merge($errors, $inheritanceValidation['errors']);
                return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
            }
        }

        // Verify root certificate's self-signature if it exists
        $rootSelfSignature = $rootCert->getSelfSignature();
        if ($rootSelfSignature !== null) {
            try {
                $dataToSign = $rootCert->toBinaryForSigning();
                $isSignatureValid = $rootSelfSignature->validate($dataToSign, $rootCert->key);

                if (!$isSignatureValid) {
                    $errors[] = new ValidationError("Invalid self-signature on root CA certificate", $rootCert, "root CA self-signature verification");
                    return ['isValid' => false, 'errors' => $errors, 'warnings' => $warnings];
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
     * Validate that a signer certificate has proper authority to sign a target certificate
     *
     * @param Certificate $certificate The certificate being signed
     * @param Certificate $signer The certificate doing the signing
     * @return array{isValid: bool, errors: ValidationError[]}
     */
    private static function validateCertificateAuthority(Certificate $certificate, Certificate $signer): array
    {
        $errors = [];

        // If target certificate is a CA certificate (has ROOT_CA, INTERMEDIATE_CA, or CA flags)
        // See SPECIFICATION.md: "Roles and combinations" and "Signing rules matrix"
        $targetIsCA = $certificate->flags->isCA();

        // SPECIFICATION.md: ROOT_CA must be self‑signed (see "Roles and combinations")
        if ($certificate->flags->hasRootCA() && !$certificate->isSelfSigned()) {
            $errors[] = new ValidationError(
                'Certificate with ROOT_CA flag must be self-signed',
                $certificate,
                'certificate authority validation'
            );
        }

        $signerHasCA = $signer->flags->hasCA();
        $signerHasIntermediate = $signer->flags->hasIntermediateCA();

        // A signer must have either CA or INTERMEDIATE_CA flag to sign anything
        // SPECIFICATION.md: "Roles and combinations"
        if (!$signerHasCA && !$signerHasIntermediate) {
            $errors[] = new ValidationError(
                'Certificate without CA or INTERMEDIATE_CA flags cannot sign other certificates',
                $signer,
                'certificate authority validation'
            );
        }

        // Enforce specific signing capabilities based on the subject
        // SPECIFICATION.md: "Signing rules matrix"
        if ($targetIsCA) {
            if (!$signerHasIntermediate) {
                $errors[] = new ValidationError(
                    'Certificate with CA flags must be signed by a certificate with INTERMEDIATE_CA flag',
                    $certificate,
                    'certificate authority validation'
                );
            }
        } else {
            if (!$signerHasCA) {
                $errors[] = new ValidationError(
                    'Non-CA certificate must be signed by a certificate with CA flag',
                    $certificate,
                    'certificate authority validation'
                );
            }
        }

        return ['isValid' => empty($errors), 'errors' => $errors];
    }

    /**
     * Validate that a certificate's end-entity flags inherit properly from its signer
     *
     * @param Certificate $certificate The certificate being signed
     * @param Certificate $signer The certificate doing the signing
     * @return array{isValid: bool, errors: ValidationError[]}
     */
    private static function validateEndEntityFlagInheritance(Certificate $certificate, Certificate $signer): array
    {
        $errors = [];

        // ROOT_CA certificates (self-signed) can have any end-entity flags
        if ($signer->isRootCA() && $certificate->key->id->equals($signer->key->id)) {
            return ['isValid' => true, 'errors' => $errors];
        }

        // Get end-entity flags for both certificates
        // SPECIFICATION.md: "End‑Entity Inheritance Matrix" and
        // "End‑entity flags (non‑CA) inheritance"
        $certificateEndEntityFlags = $certificate->flags->getEndEntityFlags();
        $signerEndEntityFlags = $signer->flags->getEndEntityFlags();

        // Certificate's end-entity flags must be a subset of signer's end-entity flags
        // SPECIFICATION.md: Subject.EndEntity ⊆ Issuer.EndEntity
        if (!$certificateEndEntityFlags->isSubsetOf($signerEndEntityFlags)) {
            $errors[] = new ValidationError(
                'Certificate end-entity flags must be a subset of signer\'s end-entity flags. Certificate has: ' .
                $certificateEndEntityFlags->toString() . ', Signer has: ' . $signerEndEntityFlags->toString(),
                $certificate,
                'end-entity flag inheritance validation'
            );
        }

        return ['isValid' => empty($errors), 'errors' => $errors];
    }
}
