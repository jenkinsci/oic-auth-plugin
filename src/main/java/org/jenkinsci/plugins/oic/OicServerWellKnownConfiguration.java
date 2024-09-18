package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import hudson.Extension;
import hudson.RelativePath;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.oidc.config.OidcConfiguration;

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

    @Restricted(NoExternalUse.class) // for testing only
    void invalidateProviderMetadata() {
        // TODO XXX test code should be refactored to not make changes
        oidcProviderMetadata = null;
    }

    /**
     * Obtain the provider configuration from the configured well known URL if it
     * has not yet been obtained or requires a refresh.
     */
    @Override
    public OIDCProviderMetadata toProviderMetadata() {
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

            oidcProviderMetadata = _oidcProviderMetadata;
            // TODO XXX need to obtain the expiry!
            setWellKnownExpires(/*response.getHeaders()*/ );
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
        throw new IllegalStateException("Well known configuration could not be loaded, login can not preceed.");
    }

    /**
     * Parse headers to determine expiration date
     */
    // XXX TODO
    private void setWellKnownExpires(/* HttpHeaders headers*/ ) {
        String expires = "0"; // Util.fixEmptyAndTrim(headers.getExpires());
        // expires 0 means no cache
        // we could (should?) have a look at Cache-Control header and max-age but for
        // simplicity
        // we can just leave it default TTL 1h refresh which sounds reasonable for such
        // file
        if (expires != null && !"0".equals(expires)) {
            ZonedDateTime zdt = ZonedDateTime.parse(expires, DateTimeFormatter.RFC_1123_DATE_TIME);
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
                // TODO XXX handle disabling SSL Verification etc..
                OidcConfiguration configuration = new OidcConfiguration();
                configuration.setClientId("ignored-but-requred");
                configuration.setSecret("ignored-but-required");
                configuration.setDiscoveryURI(wellKnownOpenIDConfigurationUrl);

                OIDCProviderMetadata providerMetadata = configuration.findProviderMetadata();

                if (providerMetadata.getAuthorizationEndpointURI() == null
                        || providerMetadata.getTokenEndpointURI() == null) {
                    return FormValidation.warning(Messages.OicSecurityRealm_URLNotAOpenIdEnpoint());
                }
                return FormValidation.ok();
            } catch (TechnicalException e) {
                if (e.getCause() instanceof ParseException) {
                    return FormValidation.error(e, Messages.OicSecurityRealm_URLNotAOpenIdEnpoint());
                }
                return FormValidation.error(e, Messages.OicSecurityRealm_ErrorRetreivingWellKnownConfig());
            }
        }

        @POST
        public FormValidation doCheckOverrideScopes(@QueryParameter String overrideScopes) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(overrideScopes) == null) {
                return FormValidation.ok();
            }
            if (!overrideScopes.toLowerCase().contains("openid")) {
                return FormValidation.warning(Messages.OicSecurityRealm_RUSureOpenIdNotInScope());
            }
            return FormValidation.ok();
        }
    }
}
