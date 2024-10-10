package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.Algorithm;
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
import java.util.function.Function;
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
    public static void filterFipsNonCompliantJweAlgorithm(List<JWEAlgorithm> algorithms) {
        filterFipsNonCompliantAlgorithms(algorithms, OicAlgorithmValidator::isJweAlgorithmFipsNonCompliant);
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
    public static void filterFipsNonCompliantJwsAlgorithm(List<JWSAlgorithm> algorithms) {
        filterFipsNonCompliantAlgorithms(algorithms, OicAlgorithmValidator::isJwsAlgorithmFipsNonCompliant);
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
    public static void filterFipsNonCompliantEncryptionMethod(List<EncryptionMethod> algorithms) {
        filterFipsNonCompliantAlgorithms(algorithms, OicAlgorithmValidator::isEncryptionMethodFipsNonCompliant);
    }

    /**
     * Filters out FIPS non-compliant algorithms from the provided list.
     *
     * @param <T> the type of the algorithm
     * @param algorithms the list of algorithms to be filtered
     * @param isNonCompliant a function that checks if an algorithm is FIPS non-compliant
     */
    public static <T extends Algorithm> void filterFipsNonCompliantAlgorithms(
            List<T> algorithms, Function<String, Boolean> isNonCompliant) {
        if (isFIPSMode && algorithms != null && !algorithms.isEmpty()) {
            List<T> itemsToBeRemoved = new ArrayList<>();
            for (T algorithm : algorithms) {
                if (isNonCompliant.apply(algorithm.getName())) {
                    itemsToBeRemoved.add(algorithm);
                }
            }
            if (!itemsToBeRemoved.isEmpty()) {
                algorithms.removeAll(itemsToBeRemoved);
            }
        }
    }
}
