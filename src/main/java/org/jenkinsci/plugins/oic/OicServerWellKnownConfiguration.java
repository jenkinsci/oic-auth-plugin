package org.jenkinsci.plugins.oic;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.json.gson.GsonFactory;
import com.google.gson.JsonParseException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Extension;
import hudson.RelativePath;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.oic.OicSecurityRealm.TokenAuthMethod;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

public class OicServerWellKnownConfiguration extends OicServerConfiguration {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(OicServerWellKnownConfiguration.class.getName());

    private final String wellKnownOpenIDConfigurationUrl;
    private String scopesOverride;

    private transient String authorizationServerUrl;
    private transient String tokenServerUrl;
    private transient String jwksServerUrl;
    private transient String endSessionUrl;
    private transient String scopes;
    private transient String userInfoServerUrl;
    private transient boolean useRefreshTokens;
    private transient TokenAuthMethod tokenAuthMethod;
    private transient String issuer;

    /**
     * Time of the wellknown configuration expiration
     */
    private transient LocalDateTime wellKnownExpires = null;

    @DataBoundConstructor
    public OicServerWellKnownConfiguration(String wellKnownOpenIDConfigurationUrl) {
        this.wellKnownOpenIDConfigurationUrl = Objects.requireNonNull(wellKnownOpenIDConfigurationUrl);
    }

    @DataBoundSetter
    public void setScopesOverride(String scopesOverride) {
        this.scopesOverride = Util.fixEmptyAndTrim(scopesOverride);
    }

    @Override
    public String getAuthorizationServerUrl() {
        loadWellKnownConfigIfNeeded();
        return authorizationServerUrl;
    }

    @Override
    @CheckForNull
    public String getEndSessionUrl() {
        loadWellKnownConfigIfNeeded();
        return endSessionUrl;
    }

    @Override
    @CheckForNull
    public String getIssuer() {
        loadWellKnownConfigIfNeeded();
        return issuer;
    }

    @Override
    public String getJwksServerUrl() {
        loadWellKnownConfigIfNeeded();
        return jwksServerUrl;
    }

    /**
     * Returns {@link #getScopesOverride()} if set, otherwise the scopes from the published metadata if set, otherwise "openid email".
     */
    @Override
    public String getScopes() {
        loadWellKnownConfigIfNeeded();
        if (scopesOverride != null) {
            return scopesOverride;
        }
        if (scopes != null) {
            return scopes;
        }
        // server did not advertise anything and no overrides set.
        // email may not be supported, but it is relatively common so try anyway
        return "openid email";
    }

    public String getScopesOverride() {
        return scopesOverride;
    }

    public String getWellKnownOpenIDConfigurationUrl() {
        return wellKnownOpenIDConfigurationUrl;
    }

    @Override
    public String getTokenServerUrl() {
        loadWellKnownConfigIfNeeded();
        return tokenServerUrl;
    }

    @Override
    public String getUserInfoServerUrl() {
        loadWellKnownConfigIfNeeded();
        return userInfoServerUrl;
    }

    @Override
    public boolean isUseRefreshTokens() {
        loadWellKnownConfigIfNeeded();
        return useRefreshTokens;
    }

    @Override
    public TokenAuthMethod getTokenAuthMethod() {
        loadWellKnownConfigIfNeeded();
        return tokenAuthMethod;
    }

    /**
     * Obtain the provider configuration from the configured well known URL if it
     * has not yet been obtained or requires a refresh.
     */
    private void loadWellKnownConfigIfNeeded() {
        LocalDateTime now = LocalDateTime.now();
        if (this.wellKnownExpires != null && this.wellKnownExpires.isBefore(now)) {
            // configuration is still fresh
            return;
        }

        // Get the well-known configuration from the specified URL
        try {
            URL url = new URL(wellKnownOpenIDConfigurationUrl);
            OicSecurityRealm realm = (OicSecurityRealm) Jenkins.get().getSecurityRealm();
            HttpRequest request =
                    realm.getHttpTransport().createRequestFactory().buildGetRequest(new GenericUrl(url));

            com.google.api.client.http.HttpResponse response = request.execute();
            WellKnownOpenIDConfigurationResponse config = GsonFactory.getDefaultInstance()
                    .fromInputStream(
                            response.getContent(),
                            Charset.defaultCharset(),
                            WellKnownOpenIDConfigurationResponse.class);

            this.authorizationServerUrl = config.getAuthorizationEndpoint();
            this.issuer = config.getIssuer();
            this.tokenServerUrl = config.getTokenEndpoint();
            this.jwksServerUrl = config.getJwksUri();
            this.tokenAuthMethod = config.getPreferredTokenAuthMethod();
            this.userInfoServerUrl = config.getUserinfoEndpoint();
            if (config.getScopesSupported() != null
                    && !config.getScopesSupported().isEmpty()) {
                this.scopes = StringUtils.join(config.getScopesSupported(), " ");
            }
            this.endSessionUrl = config.getEndSessionEndpoint();

            if (config.getGrantTypesSupported() != null) {
                this.useRefreshTokens = config.getGrantTypesSupported().contains("refresh_token");
            } else {
                this.useRefreshTokens = false;
            }

            setWellKnownExpires(response.getHeaders());
        } catch (MalformedURLException e) {
            LOGGER.log(Level.SEVERE, "Invalid WellKnown OpenID Configuration URL", e);
        } catch (HttpResponseException e) {
            LOGGER.log(Level.SEVERE, "Could not get wellknown OpenID Configuration", e);
        } catch (JsonParseException e) {
            LOGGER.log(Level.SEVERE, "Could not parse wellknown OpenID Configuration", e);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error while loading wellknown OpenID Configuration", e);
        }
    }

    /**
     * Parse headers to determine expiration date
     */
    private void setWellKnownExpires(HttpHeaders headers) {
        String expires = Util.fixEmptyAndTrim(headers.getExpires());
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
                URL url = new URL(wellKnownOpenIDConfigurationUrl);
                HttpRequest request = OicSecurityRealm.constructHttpTransport(disableSslVerification)
                        .createRequestFactory()
                        .buildGetRequest(new GenericUrl(url));
                com.google.api.client.http.HttpResponse response = request.execute();

                // Try to parse the response. If it's not valid, a JsonParseException will be
                // thrown indicating
                // that it's not a valid JSON describing an OpenID Connect endpoint
                WellKnownOpenIDConfigurationResponse config = GsonFactory.getDefaultInstance()
                        .fromInputStream(
                                response.getContent(),
                                Charset.defaultCharset(),
                                WellKnownOpenIDConfigurationResponse.class);
                if (config.getAuthorizationEndpoint() == null || config.getTokenEndpoint() == null) {
                    return FormValidation.warning(Messages.OicSecurityRealm_URLNotAOpenIdEnpoint());
                }

                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            } catch (HttpResponseException e) {
                return FormValidation.error(
                        e,
                        Messages.OicSecurityRealm_CouldNotRetreiveWellKnownConfig(
                                e.getStatusCode(), e.getStatusMessage()));
            } catch (JsonParseException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_CouldNotParseResponse());
            } catch (IOException e) {
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
