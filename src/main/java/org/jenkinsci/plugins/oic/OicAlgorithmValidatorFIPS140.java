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
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * This class helps in validating algorithms for FIPS-140 compliance and filtering the non-compliant algorithms when in
 * FIPS mode.
 */
public class OicAlgorithmValidatorFIPS140 {

    private static final Set<JWSAlgorithm> JWSSupportedAlgorithms = new LinkedHashSet<>();
    private static final Set<JWEAlgorithm> JWESupportedAlgorithms = new LinkedHashSet<>();
    private static final Set<EncryptionMethod> supportedEncryptionMethod = new LinkedHashSet<>();

    // Below list of compliant algorithms will be used to block the FIPS non-compliant algorithms.
    static {
        // Init compliant JWS algorithms
        JWSSupportedAlgorithms.addAll(MACSigner.SUPPORTED_ALGORITHMS);
        JWSSupportedAlgorithms.addAll(RSASSASigner.SUPPORTED_ALGORITHMS);
        JWSSupportedAlgorithms.addAll(ECDSASigner.SUPPORTED_ALGORITHMS);

        // Init compliant JWE algorithms
        JWESupportedAlgorithms.addAll(AESCryptoProvider.SUPPORTED_ALGORITHMS);
        JWESupportedAlgorithms.addAll(RSACryptoProvider.SUPPORTED_ALGORITHMS);
        // RSA1_5 is deprecated and not a compliant algorithm.
        JWESupportedAlgorithms.remove(JWEAlgorithm.RSA1_5);
        JWESupportedAlgorithms.addAll(ECDHCryptoProvider.SUPPORTED_ALGORITHMS);
        JWESupportedAlgorithms.addAll(PasswordBasedCryptoProvider.SUPPORTED_ALGORITHMS);

        // Init complaint EncryptionMethods
        supportedEncryptionMethod.addAll(ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
        supportedEncryptionMethod.remove(EncryptionMethod.XC20P);
    }

    /**
     * Checks if the JWS signing algorithm used for OIC configuration is FIPS-140 compliant.
     */
    public static boolean isJWSAlgorithmFipsCompliant(@NonNull JWSAlgorithm algorithm) {
        return JWSSupportedAlgorithms.contains(algorithm);
    }

    /**
     *  Checks if the JWE encryption algorithm used for OIC configuration is FIPS-140 compliant.
     */
    public static boolean isJWEAlgorithmFipsCompliant(@NonNull JWEAlgorithm algorithm) {
        return JWESupportedAlgorithms.contains(algorithm);
    }

    /**
     *  Checks if the encryption method used for OIC configuration is FIPS-140 compliant.
     */
    public static boolean isEncryptionMethodFipsCompliant(@NonNull EncryptionMethod encryptionMethod) {
        return supportedEncryptionMethod.contains(encryptionMethod);
    }

    /**
     *  Filter the list of JWE encryption lists used in OIC configuration and return only the FIPS-140 compliant
     *  algorithms
     * @return immutable list of FIPS-140 JWE encryption algorithms
     */
    @NonNull
    public static List<JWEAlgorithm> getFipsCompliantJWEAlgorithm(@NonNull List<JWEAlgorithm> algorithms) {
        return filterAlgorithms(algorithms, OicAlgorithmValidatorFIPS140::isJWEAlgorithmFipsCompliant);
    }

    /**
     *  Filter the list of JWS encryption lists used in OIC configuration and return only the FIPS-140 compliant
     *  algorithms
     * @return immutable list of FIPS-140 JWS encryption algorithms
     */
    @NonNull
    public static List<JWSAlgorithm> getFipsCompliantJWSAlgorithm(@NonNull List<JWSAlgorithm> algorithms) {
        return filterAlgorithms(algorithms, OicAlgorithmValidatorFIPS140::isJWSAlgorithmFipsCompliant);
    }

    /**
     *  Filter the list of encryption method lists used in OIC configuration and return only the FIPS-140 compliant
     *  algorithms
     * @return immutable list of FIPS-140 encryption methods
     */
    public static List<EncryptionMethod> getFipsCompliantEncryptionMethod(@NonNull List<EncryptionMethod> algorithms) {
        return filterAlgorithms(algorithms, OicAlgorithmValidatorFIPS140::isEncryptionMethodFipsCompliant);
    }

    /**
     * Filters out FIPS non-compliant algorithms from the provided list.
     *
     * @param <T> the type of the algorithm
     * @param algorithms the list of algorithms to filter
     * @param criteria that checks if an algorithm should be filtered or not
     * @return immutable filtered list with elements matching the criteria
     */
    @NonNull
    private static <T extends Algorithm> List<T> filterAlgorithms(
            @NonNull List<T> algorithms, @NonNull Function<T, Boolean> criteria) {
        return algorithms.stream().filter(criteria::apply).collect(Collectors.toList());
    }
}
