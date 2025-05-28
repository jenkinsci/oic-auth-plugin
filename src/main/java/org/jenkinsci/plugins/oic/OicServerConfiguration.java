package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import java.io.Serializable;
import java.util.List;
import jenkins.security.FIPS140;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

public abstract class OicServerConfiguration extends AbstractDescribableImpl<OicServerConfiguration>
        implements ExtensionPoint, Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Convert the OicServerConfiguration to {@link OIDCProviderMetadata} for use by the client.
     */
    public final OIDCProviderMetadata toProviderMetadata() {
        var providerMetadata = toProviderMetadataInternal();
        filterNonFIPS140CompliantAlgorithms(providerMetadata);
        return providerMetadata;
    }

    protected abstract OIDCProviderMetadata toProviderMetadataInternal();

    // Visible for testing
    @Restricted(NoExternalUse.class)
    protected static void filterNonFIPS140CompliantAlgorithms(@NonNull OIDCProviderMetadata oidcProviderMetadata) {
        if (FIPS140.useCompliantAlgorithms()) {
            // If FIPS is not enabled, then we don't have to filter the algorithms
            filterJwsAlgorithms(oidcProviderMetadata);
            filterJweAlgorithms(oidcProviderMetadata);
            filterEncryptionMethods(oidcProviderMetadata);
        }
    }

    private static void filterEncryptionMethods(@NonNull OIDCProviderMetadata oidcProviderMetadata) {
        if (oidcProviderMetadata.getRequestObjectJWEEncs() != null) {
            List<EncryptionMethod> requestObjectJWEEncs = OicAlgorithmValidatorFIPS140.getFipsCompliantEncryptionMethod(
                    oidcProviderMetadata.getRequestObjectJWEEncs());
            oidcProviderMetadata.setRequestObjectJWEEncs(requestObjectJWEEncs);
        }

        if (oidcProviderMetadata.getAuthorizationJWEEncs() != null) {
            List<EncryptionMethod> authorizationJWEEncs = OicAlgorithmValidatorFIPS140.getFipsCompliantEncryptionMethod(
                    oidcProviderMetadata.getAuthorizationJWEEncs());
            oidcProviderMetadata.setAuthorizationJWEEncs(authorizationJWEEncs);
        }

        if (oidcProviderMetadata.getIDTokenJWEEncs() != null) {
            List<EncryptionMethod> idTokenJWEEncs = OicAlgorithmValidatorFIPS140.getFipsCompliantEncryptionMethod(
                    oidcProviderMetadata.getIDTokenJWEEncs());
            oidcProviderMetadata.setIDTokenJWEEncs(idTokenJWEEncs);
        }

        if (oidcProviderMetadata.getUserInfoJWEEncs() != null) {
            List<EncryptionMethod> userInfoJWEEncs = OicAlgorithmValidatorFIPS140.getFipsCompliantEncryptionMethod(
                    oidcProviderMetadata.getUserInfoJWEEncs());
            oidcProviderMetadata.setUserInfoJWEEncs(userInfoJWEEncs);
        }

        if (oidcProviderMetadata.getRequestObjectJWEEncs() != null) {
            List<EncryptionMethod> requestObjectJweEncs = OicAlgorithmValidatorFIPS140.getFipsCompliantEncryptionMethod(
                    oidcProviderMetadata.getRequestObjectJWEEncs());
            oidcProviderMetadata.setRequestObjectJWEEncs(requestObjectJweEncs);
        }

        if (oidcProviderMetadata.getAuthorizationJWEEncs() != null) {
            List<EncryptionMethod> authJweEncs = OicAlgorithmValidatorFIPS140.getFipsCompliantEncryptionMethod(
                    oidcProviderMetadata.getAuthorizationJWEEncs());
            oidcProviderMetadata.setAuthorizationJWEEncs(authJweEncs);
        }
    }

    private static void filterJweAlgorithms(@NonNull OIDCProviderMetadata oidcProviderMetadata) {
        if (oidcProviderMetadata.getIDTokenJWEAlgs() != null) {
            List<JWEAlgorithm> idTokenJWEAlgs =
                    OicAlgorithmValidatorFIPS140.getFipsCompliantJWEAlgorithm(oidcProviderMetadata.getIDTokenJWEAlgs());
            oidcProviderMetadata.setIDTokenJWEAlgs(idTokenJWEAlgs);
        }

        if (oidcProviderMetadata.getUserInfoJWEAlgs() != null) {
            List<JWEAlgorithm> userTokenJWEAlgs = OicAlgorithmValidatorFIPS140.getFipsCompliantJWEAlgorithm(
                    oidcProviderMetadata.getUserInfoJWEAlgs());
            oidcProviderMetadata.setUserInfoJWEAlgs(userTokenJWEAlgs);
        }

        if (oidcProviderMetadata.getRequestObjectJWEAlgs() != null) {
            List<JWEAlgorithm> requestObjectJWEAlgs = OicAlgorithmValidatorFIPS140.getFipsCompliantJWEAlgorithm(
                    oidcProviderMetadata.getRequestObjectJWEAlgs());
            oidcProviderMetadata.setRequestObjectJWEAlgs(requestObjectJWEAlgs);
        }

        if (oidcProviderMetadata.getAuthorizationJWEAlgs() != null) {
            List<JWEAlgorithm> authorizationJWEAlgs = OicAlgorithmValidatorFIPS140.getFipsCompliantJWEAlgorithm(
                    oidcProviderMetadata.getAuthorizationJWEAlgs());
            oidcProviderMetadata.setAuthorizationJWEAlgs(authorizationJWEAlgs);
        }
    }

    private static void filterJwsAlgorithms(@NonNull OIDCProviderMetadata oidcProviderMetadata) {
        if (oidcProviderMetadata.getIDTokenJWSAlgs() != null) {
            List<JWSAlgorithm> idTokenJWSAlgs =
                    OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(oidcProviderMetadata.getIDTokenJWSAlgs());
            oidcProviderMetadata.setIDTokenJWSAlgs(idTokenJWSAlgs);
        }

        if (oidcProviderMetadata.getUserInfoJWSAlgs() != null) {
            List<JWSAlgorithm> userInfoJwsAlgo = OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(
                    oidcProviderMetadata.getUserInfoJWSAlgs());
            oidcProviderMetadata.setUserInfoJWSAlgs(userInfoJwsAlgo);
        }

        if (oidcProviderMetadata.getTokenEndpointJWSAlgs() != null) {
            List<JWSAlgorithm> tokenEndpointJWSAlgs = OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(
                    oidcProviderMetadata.getTokenEndpointJWSAlgs());
            oidcProviderMetadata.setTokenEndpointJWSAlgs(tokenEndpointJWSAlgs);
        }

        if (oidcProviderMetadata.getIntrospectionEndpointJWSAlgs() != null) {
            List<JWSAlgorithm> introspectionEndpointJWSAlgs = OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(
                    oidcProviderMetadata.getIntrospectionEndpointJWSAlgs());
            oidcProviderMetadata.setIntrospectionEndpointJWSAlgs(introspectionEndpointJWSAlgs);
        }

        if (oidcProviderMetadata.getRevocationEndpointJWSAlgs() != null) {
            List<JWSAlgorithm> revocationEndpointJWSAlgs = OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(
                    oidcProviderMetadata.getRevocationEndpointJWSAlgs());
            oidcProviderMetadata.setRevocationEndpointJWSAlgs(revocationEndpointJWSAlgs);
        }

        if (oidcProviderMetadata.getRequestObjectJWSAlgs() != null) {
            List<JWSAlgorithm> requestObjectJWSAlgs = OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(
                    oidcProviderMetadata.getRequestObjectJWSAlgs());
            oidcProviderMetadata.setRequestObjectJWSAlgs(requestObjectJWSAlgs);
        }

        if (oidcProviderMetadata.getDPoPJWSAlgs() != null) {
            List<JWSAlgorithm> dPoPJWSAlgs =
                    OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(oidcProviderMetadata.getDPoPJWSAlgs());
            oidcProviderMetadata.setDPoPJWSAlgs(dPoPJWSAlgs);
        }

        if (oidcProviderMetadata.getAuthorizationJWSAlgs() != null) {
            List<JWSAlgorithm> authorizationJWSAlgs = OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(
                    oidcProviderMetadata.getAuthorizationJWSAlgs());
            oidcProviderMetadata.setAuthorizationJWSAlgs(authorizationJWSAlgs);
        }

        if (oidcProviderMetadata.getBackChannelAuthenticationRequestJWSAlgs() != null) {
            List<JWSAlgorithm> backChannelAuthenticationRequestJWSAlgs =
                    OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(
                            oidcProviderMetadata.getBackChannelAuthenticationRequestJWSAlgs());
            oidcProviderMetadata.setBackChannelAuthenticationRequestJWSAlgs(backChannelAuthenticationRequestJWSAlgs);
        }

        if (oidcProviderMetadata.getClientRegistrationAuthnJWSAlgs() != null) {
            List<JWSAlgorithm> clientRegisterationAuth = OicAlgorithmValidatorFIPS140.getFipsCompliantJWSAlgorithm(
                    oidcProviderMetadata.getClientRegistrationAuthnJWSAlgs());
            oidcProviderMetadata.setClientRegistrationAuthnJWSAlgs(clientRegisterationAuth);
        }
    }
}
