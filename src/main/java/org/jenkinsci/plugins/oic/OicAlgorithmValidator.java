package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.impl.AESCryptoProvider;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.ECDHCryptoProvider;
import com.nimbusds.jose.crypto.impl.PasswordBasedCryptoProvider;
import com.nimbusds.jose.crypto.impl.RSACryptoProvider;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import jenkins.security.FIPS140;

/**
 * This class helps in validating algorithms for FIPS compliance and filtering the non-compliant algorithms when in
 * FIPS mode.
 */
public class OicAlgorithmValidator {

    private static final boolean isFIPSMode = FIPS140.useCompliantAlgorithms();

    /**
     * Checks if the Jws signing algorithm used for OIC configuration is FIPS compliant.
     */
    public static boolean isJwsAlgorithmFipsNonCompliant(String algorithm) {
        boolean matchNotFound = false;
        if (isFIPSMode && algorithm != null) {
            Set<JWSAlgorithm> jwsSupportedAlgorithms = new LinkedHashSet<>();
            jwsSupportedAlgorithms.addAll(MACSigner.SUPPORTED_ALGORITHMS);
            jwsSupportedAlgorithms.addAll(RSASSASigner.SUPPORTED_ALGORITHMS);
            jwsSupportedAlgorithms.addAll(ECDSASigner.SUPPORTED_ALGORITHMS);

            if (!jwsSupportedAlgorithms.isEmpty()) {
                matchNotFound = jwsSupportedAlgorithms.stream()
                        .map(JWSAlgorithm::getName)
                        .noneMatch(name -> name.equals(algorithm));
            }
        }
        return matchNotFound;
    }

    /**
     *  Checks if the Jwe encryption algorithm used for OIC configuration is FIPS compliant.
     */
    public static boolean isJweAlgorithmFipsNonCompliant(String algorithm) {
        boolean matchNotFound = false;
        if (isFIPSMode && algorithm != null) {
            Set<JWEAlgorithm> jweSupportedAlgorithms = new LinkedHashSet<>();
            jweSupportedAlgorithms.addAll(AESCryptoProvider.SUPPORTED_ALGORITHMS);
            jweSupportedAlgorithms.addAll(RSACryptoProvider.SUPPORTED_ALGORITHMS);
            // RSA1_5 is deprecated and not a compliant algorithm.
            jweSupportedAlgorithms.remove(JWEAlgorithm.RSA1_5);
            jweSupportedAlgorithms.addAll(ECDHCryptoProvider.SUPPORTED_ALGORITHMS);
            jweSupportedAlgorithms.addAll(PasswordBasedCryptoProvider.SUPPORTED_ALGORITHMS);

            if (!jweSupportedAlgorithms.isEmpty()) {
                matchNotFound = jweSupportedAlgorithms.stream()
                        .map(JWEAlgorithm::getName)
                        .noneMatch(name -> name.equals(algorithm));
            }
        }
        return matchNotFound;
    }

    /**
     *  Filter FIPS non-compliant Jwe encryption algorithm used for OIC configuration.
     */
    public static void filterFipsNonCompliantJweAlgorithm(List<JWEAlgorithm> algorithm) {
        boolean matchNotFound = false;
        if (isFIPSMode && algorithm != null && !algorithm.isEmpty()) {
            List<JWEAlgorithm> itemsToBeRemoved = new ArrayList<>();
            for (JWEAlgorithm jweAlgorithm : algorithm) {
                matchNotFound = isJweAlgorithmFipsNonCompliant(jweAlgorithm.getName());
                if (matchNotFound) {
                    itemsToBeRemoved.add(jweAlgorithm);
                }
            }
            if (!itemsToBeRemoved.isEmpty()) {
                algorithm.removeAll(itemsToBeRemoved);
            }
        }
    }

    /**
     *  validate FIPS non-compliant Jwe encryption algorithm used for OIC configuration.
     */
    public static boolean isJwsAlgoFipsNonCompliant(List<JWSAlgorithm> algorithm) {
        boolean matchNotFound = false;
        if (isFIPSMode && algorithm != null && !algorithm.isEmpty()) {
            for (JWSAlgorithm jwsAlgorithm : algorithm) {
                matchNotFound = isJwsAlgorithmFipsNonCompliant(jwsAlgorithm.getName());
                if (matchNotFound) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     *  Filter FIPS non-compliant Jws encryption algorithm used for OIC configuration.
     */
    public static void filterFipsNonCompliantJwsAlgorithm(List<JWSAlgorithm> algorithm) {
        boolean matchNotFound = false;
        if (isFIPSMode && algorithm != null && !algorithm.isEmpty()) {
            List<JWSAlgorithm> itemsToBeRemoved = new ArrayList<>();
            for (JWSAlgorithm jwsAlgorithm : algorithm) {
                matchNotFound = isJwsAlgorithmFipsNonCompliant(jwsAlgorithm.getName());
                if (matchNotFound) {
                    itemsToBeRemoved.add(jwsAlgorithm);
                }
            }
            if (!itemsToBeRemoved.isEmpty()) {
                algorithm.removeAll(itemsToBeRemoved);
            }
        }
    }

    /**
     *  Checks if the encryption method used for OIC configuration is FIPS compliant.
     */
    public static boolean isEncryptionMethodFipsNonCompliant(String encryptionMethod) {
        boolean matchNotFound = false;
        if (isFIPSMode && encryptionMethod != null) {
            Set<EncryptionMethod> supportedEncryptionMethod =
                    new LinkedHashSet<>(ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
            if (!supportedEncryptionMethod.isEmpty()) {
                matchNotFound = supportedEncryptionMethod.stream()
                        .map(EncryptionMethod::getName)
                        .noneMatch(name -> name.equals(encryptionMethod));
            }
        }
        return matchNotFound;
    }

    /**
     *  Filter FIPS non-compliant encryption algorithm used for OIC configuration.
     */
    public static void filterFipsNonCompliantEncryptionMethod(List<EncryptionMethod> algorithm) {
        boolean matchNotFound = false;
        if (isFIPSMode && algorithm != null && !algorithm.isEmpty()) {
            List<EncryptionMethod> itemsToBeRemoved = new ArrayList<>();
            for (EncryptionMethod encryptionMethod : algorithm) {
                matchNotFound = isEncryptionMethodFipsNonCompliant(encryptionMethod.getName());
                if (matchNotFound) {
                    itemsToBeRemoved.add(encryptionMethod);
                }
            }
            if (!itemsToBeRemoved.isEmpty()) {
                algorithm.removeAll(itemsToBeRemoved);
            }
        }
    }
}
