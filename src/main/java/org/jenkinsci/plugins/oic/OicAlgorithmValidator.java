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
 * This class helps in validating algorithms for FIPS-140 compliance and filtering the non-compliant algorithms when in
 * FIPS mode.
 */
public class OicAlgorithmValidatorFIPS140 {

    private static final boolean isFIPSMode = FIPS140.useCompliantAlgorithms();
    private static final Set<JWSAlgorithm> jwsSupportedAlgorithms = new LinkedHashSet<>();
    private static final Set<JWEAlgorithm> jweSupportedAlgorithms = new LinkedHashSet<>();
    private static final Set<EncryptionMethod> supportedEncryptionMethod = new LinkedHashSet<>();

    // Below list of compliant algorithms will be used to block the FIPS non-compliant algorithms.
    static {
        // Init compliant Jws algorithms
        jwsSupportedAlgorithms.addAll(MACSigner.SUPPORTED_ALGORITHMS);
        jwsSupportedAlgorithms.addAll(RSASSASigner.SUPPORTED_ALGORITHMS);
        jwsSupportedAlgorithms.addAll(ECDSASigner.SUPPORTED_ALGORITHMS);

        // Init compliant Jwe algorithms
        jweSupportedAlgorithms.addAll(AESCryptoProvider.SUPPORTED_ALGORITHMS);
        jweSupportedAlgorithms.addAll(RSACryptoProvider.SUPPORTED_ALGORITHMS);
        // RSA1_5 is deprecated and not a compliant algorithm.
        jweSupportedAlgorithms.remove(JWEAlgorithm.RSA1_5);
        jweSupportedAlgorithms.addAll(ECDHCryptoProvider.SUPPORTED_ALGORITHMS);
        jweSupportedAlgorithms.addAll(PasswordBasedCryptoProvider.SUPPORTED_ALGORITHMS);

        // Init complaint EncryptionMethods
        supportedEncryptionMethod.addAll(ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
        // XC20P is not complaint method
        supportedEncryptionMethod.remove(EncryptionMethod.XC20P);
    }

    /**
     * Checks if the Jws signing algorithm used for OIC configuration is FIPS compliant.
     */
    public static boolean isJwsAlgorithmFipsNonCompliant(Algorithm algorithm) {
        boolean matchNotFound = false;
        if (isFIPSMode && algorithm != null) {
            matchNotFound = jwsSupportedAlgorithms.stream().noneMatch(jwsAlgorithm -> jwsAlgorithm.equals(algorithm));
        }
        return matchNotFound;
    }

    /**
     *  Checks if the Jwe encryption algorithm used for OIC configuration is FIPS compliant.
     */
    public static boolean isJweAlgorithmFipsNonCompliant(Algorithm algorithm) {
        boolean matchNotFound = false;
        if (isFIPSMode && algorithm != null) {
            matchNotFound = jweSupportedAlgorithms.stream().noneMatch(jweAlgorithm -> jweAlgorithm.equals(algorithm));
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
        if (isFIPSMode && algorithm != null) {
            for (JWSAlgorithm jwsAlgorithm : algorithm) {
                matchNotFound = isJwsAlgorithmFipsNonCompliant(jwsAlgorithm);
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
    public static boolean isEncryptionMethodFipsNonCompliant(Algorithm encryptionMethod) {
        boolean matchNotFound = false;
        if (isFIPSMode && encryptionMethod != null) {
            matchNotFound = supportedEncryptionMethod.stream().noneMatch(method -> method.equals(encryptionMethod));
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
            List<T> algorithms, Function<Algorithm, Boolean> isNonCompliant) {
        if (isFIPSMode && algorithms != null && !algorithms.isEmpty()) {
            List<T> itemsToBeRemoved = new ArrayList<>();
            for (T algorithm : algorithms) {
                if (isNonCompliant.apply(algorithm)) {
                    itemsToBeRemoved.add(algorithm);
                }
            }
            if (!itemsToBeRemoved.isEmpty()) {
                algorithms.removeAll(itemsToBeRemoved);
            }
        }
    }
}
