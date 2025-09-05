package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Extension;
import hudson.RelativePath;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.http.HttpHeaders;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import javax.net.ssl.SSLException;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

public class OicServerWellKnownConfiguration extends OicServerConfiguration {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(OicServerWellKnownConfiguration.class.getName());

    private final String wellKnownOpenIDConfigurationUrl;
    private String scopesOverride;

    /**
     * Time of the wellknown configuration expiration
     */
    private transient LocalDateTime wellKnownExpires = null;

    private transient volatile OIDCProviderMetadata oidcProviderMetadata;

    @DataBoundConstructor
    public OicServerWellKnownConfiguration(String wellKnownOpenIDConfigurationUrl) {
        this.wellKnownOpenIDConfigurationUrl = Objects.requireNonNull(wellKnownOpenIDConfigurationUrl);
    }

    @DataBoundSetter
    public void setScopesOverride(String scopesOverride) {
        this.scopesOverride = Util.fixEmptyAndTrim(scopesOverride);
    }

    public String getScopesOverride() {
        return scopesOverride;
    }

    public String getWellKnownOpenIDConfigurationUrl() {
        return wellKnownOpenIDConfigurationUrl;
    }

    @Restricted(DoNotUse.class) // for testing only
    void invalidateProviderMetadata() {
        oidcProviderMetadata = null;
    }

    /**
     * Obtain the provider configuration from the configured well known URL if it
     * has not yet been obtained or requires a refresh.
     */
    @Override
    protected OIDCProviderMetadata toProviderMetadataInternal() {
        // we perform this download manually rather than letting pac4j perform it
        // so that we can cache and expire the result.
        // pac4j will cache the result yet never expire it.
        LocalDateTime now = LocalDateTime.now();
        if (this.wellKnownExpires != null && this.wellKnownExpires.isBefore(now)) {
            // configuration is still fresh
            return oidcProviderMetadata;
        }

        // Download OIDC metadata
        // we need to configure timeouts, headers as well as SSL (hostname verifier etc..)
        // which may be disabled in the configuration
        ResourceRetriever rr = ((OicSecurityRealm) (Jenkins.get().getSecurityRealm())).getResourceRetriever();
        try {
            OIDCProviderMetadata _oidcProviderMetadata =
                    OIDCProviderMetadata.parse(rr.retrieveResource(new URL(wellKnownOpenIDConfigurationUrl))
                            .getContent());
            String _scopesOverride = getScopesOverride();
            if (_scopesOverride != null) {
                // split the scopes by space
                String[] splitScopes = _scopesOverride.split("\\s+");
                _oidcProviderMetadata.setScopes(new Scope(splitScopes));
            }
            // we do not expose enough to be able to configure all authentication methods,
            // so limit supported auth methods to CLIENT_SECRET_BASIC / CLIENT_SECRET_POST
            List<ClientAuthenticationMethod> tokenEndpointAuthMethods =
                    _oidcProviderMetadata.getTokenEndpointAuthMethods();
            if (tokenEndpointAuthMethods != null) {
                List<ClientAuthenticationMethod> filteredEndpointAuthMethods =
                        new ArrayList<>(tokenEndpointAuthMethods);
                filteredEndpointAuthMethods.removeIf(cam -> cam != ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        && cam != ClientAuthenticationMethod.CLIENT_SECRET_POST);
                if (filteredEndpointAuthMethods.isEmpty()) {
                    LOGGER.log(
                            Level.WARNING,
                            "OIDC well-known configuration reports only unsupported token authentication methods (authentication may not work): "
                                    + tokenEndpointAuthMethods.stream()
                                            .map(Object::toString)
                                            .collect(Collectors.joining(",", "[", "]")));
                    _oidcProviderMetadata.setTokenEndpointAuthMethods(null);
                } else {
                    _oidcProviderMetadata.setTokenEndpointAuthMethods(filteredEndpointAuthMethods);
                }
            }
            // do not allow the "none" singing algorithm for security
            List<JWSAlgorithm> idTokenJWSAlgs = _oidcProviderMetadata.getIDTokenJWSAlgs();
            if (idTokenJWSAlgs != null && idTokenJWSAlgs.contains(Algorithm.NONE)) {
                ArrayList<JWSAlgorithm> _idTokenJWSAlgs = new ArrayList<>(idTokenJWSAlgs);
                _idTokenJWSAlgs.remove(Algorithm.NONE);
                _oidcProviderMetadata.setIDTokenJWSAlgs(_idTokenJWSAlgs);
            }
            oidcProviderMetadata = _oidcProviderMetadata;
            // we have no access to the HTTP Headers to be able to find a expirey headers.
            // for now use the default expirey of 1hr.
            // we are already calling HTTP endpoints as part of the flow, so making one extra call an hour
            // should not cause any issues.
            // once this is validate, the OicSecurityRealm can be simplified to cache the built client
            // and have a periodic task to invalidate it when auto config is being used.
            setWellKnownExpires(null);
            return oidcProviderMetadata;
        } catch (MalformedURLException e) {
            LOGGER.log(Level.SEVERE, "Invalid WellKnown OpenID Configuration URL", e);
        } catch (ParseException e) {
            LOGGER.log(Level.SEVERE, "Could not parse wellknown OpenID Configuration", e);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error while loading wellknown OpenID Configuration", e);
        }
        if (oidcProviderMetadata != null) {
            // return the previously downloaded but expired copy with the hope it still works.
            // although if the well known url is down it is unlikely the rest of the provider is healthy, still. we can
            // hope.
            return oidcProviderMetadata;
        }
        throw new IllegalStateException("Well known configuration could not be loaded, login can not proceed.");
    }

    /**
     * Parse headers to determine expiration date.
     * Sets the expiry time to 1 hour from the current time if the header is not available.
     */
    private void setWellKnownExpires(@CheckForNull HttpHeaders headers) {
        Optional<String> expires = headers == null ? Optional.empty() : headers.firstValue("Expires");
        // expires 0 means no cache
        // we could (should?) have a look at Cache-Control header and max-age but for
        // simplicity we can just leave it default TTL 1h refresh which sounds reasonable for such file
        if (expires.isPresent() && !"0".equals(expires.get())) {
            ZonedDateTime zdt = ZonedDateTime.parse(expires.get(), DateTimeFormatter.RFC_1123_DATE_TIME);
            if (zdt != null) {
                this.wellKnownExpires = zdt.toLocalDateTime();
                return;
            }
        }

        // default to 1 hour refresh
        this.wellKnownExpires = LocalDateTime.now().plusSeconds(3600);
    }

    @Extension
    @Symbol("wellKnown")
    public static class DescriptorImpl extends Descriptor<OicServerConfiguration> {

        @Override
        public String getDisplayName() {
            return Messages.OicServerWellKnownConfiguration_DisplayName();
        }

        @POST
        public FormValidation doCheckWellKnownOpenIDConfigurationUrl(
                @QueryParameter String wellKnownOpenIDConfigurationUrl,
                @RelativePath("..") @QueryParameter boolean disableSslVerification) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (wellKnownOpenIDConfigurationUrl == null || wellKnownOpenIDConfigurationUrl.isBlank()) {
                return FormValidation.error(Messages.OicSecurityRealm_NotAValidURL());
            }
            try {
                ProxyAwareResourceRetriever prr =
                        ProxyAwareResourceRetriever.createProxyAwareResourceRetriver(disableSslVerification);

                OIDCProviderMetadata providerMetadata =
                        OIDCProviderMetadata.parse(prr.retrieveResource(new URL(wellKnownOpenIDConfigurationUrl))
                                .getContent());

                if (providerMetadata.getAuthorizationEndpointURI() == null
                        || providerMetadata.getTokenEndpointURI() == null) {
                    return FormValidation.warning(Messages.OicSecurityRealm_URLNotAOpenIdEnpoint());
                }
                return FormValidation.ok();
            } catch (SSLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_SSLErrorRetreivingWellKnownConfig());
            } catch (IOException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_ErrorRetreivingWellKnownConfig());
            } catch (ParseException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_URLNotAOpenIdEnpoint());
            }
        }

        @POST
        public FormValidation doCheckScopesOverride(@QueryParameter String scopesOverride) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(scopesOverride) == null) {
                return FormValidation.ok();
            }
            if (!scopesOverride.toLowerCase().contains("openid")) {
                return FormValidation.warning(Messages.OicSecurityRealm_RUSureOpenIdNotInScope());
            }
            return FormValidation.ok();
        }
    }
}
