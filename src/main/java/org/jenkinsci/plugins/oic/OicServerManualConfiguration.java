package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import hudson.util.FormValidation;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import jenkins.model.Jenkins;
import jenkins.security.FIPS140;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.oic.OicSecurityRealm.TokenAuthMethod;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

public class OicServerManualConfiguration extends OicServerConfiguration {

    private static final long serialVersionUID = 1L;

    private final String authorizationServerUrl;
    private final String tokenServerUrl;
    private TokenAuthMethod tokenAuthMethod = TokenAuthMethod.client_secret_post;
    private String jwksServerUrl;
    private String endSessionUrl;
    private String scopes = "openid email";
    private String userInfoServerUrl;
    private boolean useRefreshTokens;
    private String issuer;

    @DataBoundConstructor
    public OicServerManualConfiguration(String issuer, String tokenServerUrl, String authorizationServerUrl)
            throws FormException {
        this.issuer = validateNonNull("issuer", issuer);
        this.authorizationServerUrl = validateNonNull("authorizationServerUrl", authorizationServerUrl);
        this.tokenServerUrl = validateNonNull("tokenServerUrl", tokenServerUrl);
    }

    @DataBoundSetter
    public void setTokenAuthMethod(TokenAuthMethod tokenAuthMethod) throws FormException {
        this.tokenAuthMethod = validateNonNull("tokenAuthMethod", tokenAuthMethod);
    }

    @DataBoundSetter
    public void setEndSessionUrl(@Nullable String endSessionUrl) {
        this.endSessionUrl = Util.fixEmptyAndTrim(endSessionUrl);
    }

    @DataBoundSetter
    public void setJwksServerUrl(@Nullable String jwksServerUrl) {
        this.jwksServerUrl = Util.fixEmptyAndTrim(jwksServerUrl);
    }

    @DataBoundSetter
    public void setScopes(@NonNull String scopes) {
        this.scopes = Objects.requireNonNull(scopes);
    }

    @DataBoundSetter
    public void setUserInfoServerUrl(@Nullable String userInfoServerUrl) {
        this.userInfoServerUrl = Util.fixEmptyAndTrim(userInfoServerUrl);
    }

    @DataBoundSetter
    public void setUseRefreshTokens(boolean useRefreshTokens) {
        this.useRefreshTokens = useRefreshTokens;
    }

    public String getAuthorizationServerUrl() {
        return authorizationServerUrl;
    }

    public String getEndSessionUrl() {
        return endSessionUrl;
    }

    public String getIssuer() {
        return issuer;
    }

    public boolean isUseRefreshTokens() {
        return useRefreshTokens;
    }

    public String getJwksServerUrl() {
        return jwksServerUrl;
    }

    public String getScopes() {
        return scopes;
    }

    public TokenAuthMethod getTokenAuthMethod() {
        return tokenAuthMethod;
    }

    public String getTokenServerUrl() {
        return tokenServerUrl;
    }

    public String getUserInfoServerUrl() {
        return userInfoServerUrl;
    }

    @Override
    protected OIDCProviderMetadata toProviderMetadataInternal() {
        try {
            final OIDCProviderMetadata providerMetadata;
            if (jwksServerUrl == null) {
                // will only work if token validation is disabled in the security realm.
                providerMetadata = new OIDCProviderMetadata(
                        new Issuer(issuer),
                        List.of(SubjectType.PUBLIC),
                        List.of(ClientRegistrationType.AUTOMATIC),
                        null,
                        null,
                        new JWKSet());
            } else {
                providerMetadata = new OIDCProviderMetadata(
                        new Issuer(issuer), List.of(SubjectType.PUBLIC), new URI(jwksServerUrl));
            }
            if (isUseRefreshTokens()) {
                providerMetadata.setGrantTypes(List.of(GrantType.REFRESH_TOKEN));
            }

            providerMetadata.setUserInfoEndpointURI(toURIOrNull(userInfoServerUrl));
            providerMetadata.setEndSessionEndpointURI(toURIOrNull(endSessionUrl));
            providerMetadata.setAuthorizationEndpointURI(new URI(authorizationServerUrl));
            providerMetadata.setTokenEndpointURI(toURIOrNull(tokenServerUrl));
            providerMetadata.setJWKSetURI(toURIOrNull(jwksServerUrl));
            providerMetadata.setTokenEndpointAuthMethods(List.of(getClientAuthenticationMethod()));
            providerMetadata.setScopes(Scope.parse(getScopes()));
            // should really be a UI option, but was not previously
            // server is mandated to support HS256 but if we do not specify things that it produces
            // then they would never be checked.
            // rather we just say "I support anything, and let the check for the specific ones fail and fall through
            ArrayList<JWSAlgorithm> allAlgorithms = new ArrayList<>(JWSAlgorithm.Family.HMAC_SHA);
            if (FIPS140.useCompliantAlgorithms()) {
                // In FIPS-140 Family.ED is not supported
                allAlgorithms.addAll(JWSAlgorithm.Family.RSA);
                allAlgorithms.addAll(JWSAlgorithm.Family.EC);
            } else {
                allAlgorithms.addAll(JWSAlgorithm.Family.SIGNATURE);
            }
            providerMetadata.setIDTokenJWSAlgs(allAlgorithms);
            return providerMetadata;
        } catch (URISyntaxException e) {
            throw new IllegalStateException("could not create provider metadata", e);
        }
    }

    private ClientAuthenticationMethod getClientAuthenticationMethod() {
        if (tokenAuthMethod == TokenAuthMethod.client_secret_post) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        }
        return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
    }

    private static <T> T validateNonNull(String fieldName, T value) throws FormException {
        if (value == null) {
            throw new FormException(fieldName + " is mandatory", fieldName);
        }
        return value;
    }

    /**
     * Convert the given string to a URI or null if the string is null or blank;
     * @param uri a string representing a URI or {@code null}
     * @return a new URI representing the provided string or null.
     * @throws URISyntaxException if {@code uri} can not be converted to a {@link URI}
     */
    @CheckForNull
    private static URI toURIOrNull(String uri) throws URISyntaxException {
        if (uri == null || uri.isBlank()) {
            return null;
        }
        return new URI(uri);
    }

    @Extension
    @Symbol("manual")
    public static class DescriptorImpl extends Descriptor<OicServerConfiguration> {

        @Override
        public String getDisplayName() {
            return Messages.OicServerManualConfiguration_DisplayName();
        }

        @POST
        public FormValidation doCheckAuthorizationServerUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (value == null) {
                return FormValidation.error(Messages.OicSecurityRealm_TokenServerURLKeyRequired());
            }
            try {
                new URL(value);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @POST
        public FormValidation doCheckEndSessionUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_EndSessionURLKeyRequired());
            }
            try {
                new URL(value);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @POST
        public FormValidation doCheckIssuer(@QueryParameter String issuer) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(issuer) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_IssuerRequired());
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckJwksServerUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.ok();
            }
            try {
                new URL(value);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @POST
        public FormValidation doCheckScopes(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_ScopesRequired());
            }
            if (!value.toLowerCase(Locale.ROOT).contains("openid")) {
                return FormValidation.warning(Messages.OicSecurityRealm_RUSureOpenIdNotInScope());
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckTokenServerUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_TokenServerURLKeyRequired());
            }
            try {
                new URL(value);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @POST
        public FormValidation doCheckTokenAuthMethod(@QueryParameter String tokenAuthMethod) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(tokenAuthMethod) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_TokenAuthMethodRequired());
            }
            return FormValidation.ok();
        }
    }
}
