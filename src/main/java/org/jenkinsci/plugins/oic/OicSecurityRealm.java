/*
 * The MIT License
 *
 * Copyright (c) 2016  Michael Bischoff & GeriMedica - www.gerimedica.nl
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.oic;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential.AccessMethod;
import com.google.api.client.auth.openidconnect.HttpTransportFactory;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpExecuteInterceptor;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.util.ArrayMap;
import com.google.api.client.util.Data;
import com.google.common.base.Strings;
import com.google.gson.JsonParseException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.util.HttpResponses;
import hudson.util.Secret;
import io.burt.jmespath.Expression;
import io.burt.jmespath.JmesPath;
import io.burt.jmespath.RuntimeConfiguration;
import io.burt.jmespath.jcf.JcfRuntime;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * Login with OpenID Connect / OAuth 2
 *
 * @author Michael Bischoff
 * @author Steve Arch
 */
@SuppressWarnings("deprecation")
public class OicSecurityRealm extends SecurityRealm implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(OicSecurityRealm.class.getName());

    public static enum TokenAuthMethod {
        client_secret_basic,
        client_secret_post
    };

    private static final String ID_TOKEN_REQUEST_ATTRIBUTE = "oic-id-token";
    private static final String STATE_REQUEST_ATTRIBUTE = "oic-state";
    private static final String NO_SECRET = "none";

    private final String clientId;
    private final Secret clientSecret;
    private String wellKnownOpenIDConfigurationUrl = null;
    private String tokenServerUrl = null;
    private String jwksServerUrl = null;
    private TokenAuthMethod tokenAuthMethod;
    private String authorizationServerUrl = null;
    private String userInfoServerUrl = null;
    private String userNameField = "sub";
    private transient Expression<Object> userNameFieldExpr = null;
    private String tokenFieldToCheckKey = null;
    private transient Expression<Object> tokenFieldToCheckExpr = null;
    private String tokenFieldToCheckValue = null;
    private String fullNameFieldName = null;
    private transient Expression<Object> fullNameFieldExpr = null;
    private String emailFieldName = null;
    private transient Expression<Object> emailFieldExpr = null;
    private String groupsFieldName = null;
    private transient Expression<Object> groupsFieldExpr = null;
    private transient String simpleGroupsFieldName = null;
    private transient String nestedGroupFieldName = null;
    private String scopes = null;
    private final boolean disableSslVerification;
    private boolean logoutFromOpenidProvider = true;
    private String endSessionEndpoint = null;
    private String postLogoutRedirectUrl;
    private boolean escapeHatchEnabled = false;
    private String escapeHatchUsername = null;
    private Secret escapeHatchSecret = null;
    private String escapeHatchGroup = null;
    private String automanualconfigure = null;

    /** flag to clear overrideScopes
     */
    private transient Boolean overrideScopesDefined = null;

    /** Override scopes in wellknown configuration
     */
    private String overrideScopes = null;

    /** Flag indicating if root url should be taken from config or request
     *
     * Taking root url from request requires a well configured proxy/ingress
     */
    private boolean rootURLFromRequest = false;

    /** Flag to send scopes in code token request
     */
    private boolean sendScopesInTokenRequest = false;

    /** Flag to enable PKCE challenge
     */
    private boolean pkceEnabled = false;

    /** Flag to disable JWT signature verification
     */
    private boolean disableTokenVerification = false;

    /** Flag to disable nonce security
     */
    private boolean nonceDisabled = false;

    /** Date of wellknown configuration expiration
     */
    private transient LocalDateTime wellKnownExpires = null;

    /** old field that had an '/' implicitly added at the end,
     * transient because we no longer want to have this value stored
     * but it's still needed for backwards compatibility */
    private transient String endSessionUrl;

    /** Verification of IdToken and UserInfo (in jwt case)
     */
    private transient OicJsonWebTokenVerifier jwtVerifier;

    private transient HttpTransport httpTransport = null;

    /** Random generator needed for robust random wait
     */
    private static final Random RANDOM = new Random();

    /** Runtime context to compile JMESPath
     */
    private static final JmesPath<Object> JMESPATH = new JcfRuntime(
            new RuntimeConfiguration.Builder().withSilentTypeErrors(true).build());

    /**
     * @deprecated retained for backwards binary compatibility.
     */
    @Deprecated
    public OicSecurityRealm(
            String clientId,
            String clientSecret,
            String wellKnownOpenIDConfigurationUrl,
            String tokenServerUrl,
            String jwksServerUrl,
            String tokenAuthMethod,
            String authorizationServerUrl,
            String userInfoServerUrl,
            String userNameField,
            String tokenFieldToCheckKey,
            String tokenFieldToCheckValue,
            String fullNameFieldName,
            String emailFieldName,
            String scopes,
            String groupsFieldName,
            Boolean disableSslVerification,
            Boolean logoutFromOpenidProvider,
            String endSessionEndpoint,
            String postLogoutRedirectUrl,
            Boolean escapeHatchEnabled,
            String escapeHatchUsername,
            String escapeHatchSecret,
            String escapeHatchGroup,
            String automanualconfigure)
            throws IOException {
        this.disableSslVerification = Util.fixNull(disableSslVerification, Boolean.FALSE);
        this.httpTransport = constructHttpTransport(this.disableSslVerification);

        this.clientId = clientId;
        this.clientSecret = clientSecret != null && !clientSecret.toLowerCase().equals(NO_SECRET)
                ? Secret.fromString(clientSecret)
                : null;
        // last known config
        this.authorizationServerUrl = authorizationServerUrl;
        this.tokenServerUrl = tokenServerUrl;
        this.tokenAuthMethod =
                TokenAuthMethod.valueOf(StringUtils.defaultIfBlank(tokenAuthMethod, "client_secret_post"));
        this.userInfoServerUrl = userInfoServerUrl;
        this.jwksServerUrl = jwksServerUrl;
        this.setScopes(scopes);
        this.endSessionEndpoint = endSessionEndpoint;

        if ("auto".equals(automanualconfigure)
                || (Util.fixNull(automanualconfigure).isEmpty() &&
                    !Util.fixNull(wellKnownOpenIDConfigurationUrl).isEmpty())) {
            this.automanualconfigure = "auto";
            this.wellKnownOpenIDConfigurationUrl = Util.fixEmptyAndTrim(wellKnownOpenIDConfigurationUrl);
            this.loadWellKnownOpenIDConfigurationUrl();
        } else {
            this.automanualconfigure = "manual";
            this.wellKnownOpenIDConfigurationUrl = null; // Remove the autoconfig URL
        }

        this.setTokenFieldToCheckKey(tokenFieldToCheckKey);
        this.setTokenFieldToCheckValue(tokenFieldToCheckValue);
        this.setUserNameField(userNameField);
        this.setFullNameFieldName(fullNameFieldName);
        this.setEmailFieldName(emailFieldName);
        this.setGroupsFieldName(groupsFieldName);
        this.logoutFromOpenidProvider = Util.fixNull(logoutFromOpenidProvider, Boolean.TRUE);
        this.postLogoutRedirectUrl = postLogoutRedirectUrl;
        this.escapeHatchEnabled = Util.fixNull(escapeHatchEnabled, Boolean.FALSE);
        this.escapeHatchUsername = Util.fixEmptyAndTrim(escapeHatchUsername);
        this.setEscapeHatchSecret(Secret.fromString(escapeHatchSecret));
        this.escapeHatchGroup = Util.fixEmptyAndTrim(escapeHatchGroup);
    }

    @DataBoundConstructor
    public OicSecurityRealm(
            String clientId,
            String clientSecret,
            String authorizationServerUrl,
            String tokenServerUrl,
            String jwksServerUrl,
            String tokenAuthMethod,
            String userInfoServerUrl,
            String endSessionEndpoint,
            String scopes,
            String automanualconfigure,
            Boolean disableSslVerification)
            throws IOException {
        // Needed in DataBoundSetter
        this.disableSslVerification = Util.fixNull(disableSslVerification, Boolean.FALSE);
        this.httpTransport = constructHttpTransport(this.disableSslVerification);
        this.clientId = clientId;
        this.clientSecret = clientSecret != null && !clientSecret.toLowerCase().equals(NO_SECRET)
                ? Secret.fromString(clientSecret)
                : null;
        // auto/manual configuration as set in jcasc/config
        this.automanualconfigure = Util.fixNull(automanualconfigure);
        // previous values of OpenIDConnect configuration
        this.authorizationServerUrl = authorizationServerUrl;
        this.tokenServerUrl = tokenServerUrl;
        this.jwksServerUrl = jwksServerUrl;
        this.tokenAuthMethod =
                TokenAuthMethod.valueOf(StringUtils.defaultIfBlank(tokenAuthMethod, "client_secret_post"));
        this.userInfoServerUrl = userInfoServerUrl;
        this.endSessionEndpoint = endSessionEndpoint;
        this.setScopes(scopes);
    }

    protected Object readResolve() {
        if (httpTransport == null) {
            httpTransport = constructHttpTransport(isDisableSslVerification());
        }
        if (!Strings.isNullOrEmpty(endSessionUrl)) {
            try {
                Field field = getClass().getDeclaredField("endSessionEndpoint");
                field.setAccessible(true);
                field.set(this, endSessionUrl + "/");
            } catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
                LOGGER.log(Level.SEVERE, "Can't set endSessionEndpoint from old value", e);
            }
        }

        // backward compatibility with wrong groupsFieldName split
        if (Strings.isNullOrEmpty(this.groupsFieldName) && !Strings.isNullOrEmpty(this.simpleGroupsFieldName)) {
            String originalGroupFieldName = this.simpleGroupsFieldName;
            if (!Strings.isNullOrEmpty(this.nestedGroupFieldName)) {
                originalGroupFieldName += "[]." + this.nestedGroupFieldName;
            }
            this.setGroupsFieldName(originalGroupFieldName);
        } else {
            this.setGroupsFieldName(this.groupsFieldName);
        }
        // ensure Field JMESPath are computed
        this.setUserNameField(this.userNameField);
        this.setEmailFieldName(this.emailFieldName);
        this.setFullNameFieldName(this.fullNameFieldName);
        this.setTokenFieldToCheckKey(this.tokenFieldToCheckKey);
        // ensure escapeHatchSecret is encrypted
        this.setEscapeHatchSecret(this.escapeHatchSecret);
        return this;
    }

    private static HttpTransport constructHttpTransport(boolean disableSslVerification) {
        NetHttpTransport.Builder builder = new NetHttpTransport.Builder();
        builder.setConnectionFactory(new JenkinsAwareConnectionFactory());

        if (disableSslVerification) {
            try {
                builder.doNotValidateCertificate();
            } catch (GeneralSecurityException ex) {
                // we do not handle this exception...
            }
        }

        return builder.build();
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret == null ? Secret.fromString(NO_SECRET) : clientSecret;
    }

    public String getWellKnownOpenIDConfigurationUrl() {
        return wellKnownOpenIDConfigurationUrl;
    }

    public String getTokenServerUrl() {
        return tokenServerUrl;
    }

    public String getJwksServerUrl() {
        return jwksServerUrl;
    }

    public TokenAuthMethod getTokenAuthMethod() {
        return tokenAuthMethod;
    }

    public String getAuthorizationServerUrl() {
        return authorizationServerUrl;
    }

    public String getUserInfoServerUrl() {
        return userInfoServerUrl;
    }

    public String getUserNameField() {
        return userNameField;
    }

    public String getTokenFieldToCheckKey() {
        return tokenFieldToCheckKey;
    }

    public String getTokenFieldToCheckValue() {
        return tokenFieldToCheckValue;
    }

    public String getFullNameFieldName() {
        return fullNameFieldName;
    }

    public String getEmailFieldName() {
        return emailFieldName;
    }

    public String getGroupsFieldName() {
        return groupsFieldName;
    }

    public String getScopes() {
        return scopes != null ? scopes : "openid email";
    }

    public boolean isDisableSslVerification() {
        return disableSslVerification;
    }

    public boolean isLogoutFromOpenidProvider() {
        return logoutFromOpenidProvider;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public String getPostLogoutRedirectUrl() {
        return postLogoutRedirectUrl;
    }

    public boolean isEscapeHatchEnabled() {
        return escapeHatchEnabled;
    }

    public String getEscapeHatchUsername() {
        return escapeHatchUsername;
    }

    public Secret getEscapeHatchSecret() {
        return escapeHatchSecret;
    }

    public String getEscapeHatchGroup() {
        return escapeHatchGroup;
    }

    public String getAutomanualconfigure() {
        return automanualconfigure;
    }

    public boolean isOverrideScopesDefined() {
        return overrideScopes != null;
    }

    public String getOverrideScopes() {
        return overrideScopes;
    }

    public boolean isRootURLFromRequest() {
        return rootURLFromRequest;
    }

    public boolean isSendScopesInTokenRequest() {
        return sendScopesInTokenRequest;
    }

    public boolean isPkceEnabled() {
        return pkceEnabled;
    }

    public boolean isDisableTokenVerification() {
        return disableTokenVerification;
    }

    public boolean isNonceDisabled() {
        return nonceDisabled;
    }

    public boolean isAutoConfigure() {
        return "auto".equals(this.automanualconfigure);
    }

    /** request wellknown config of provider and update it (if required)
     */
    private void loadWellKnownOpenIDConfigurationUrl() {
        if (!isAutoConfigure() || this.wellKnownOpenIDConfigurationUrl == null) {
            // not configured
            return;
        }

        LocalDateTime now = LocalDateTime.now();
        if (this.wellKnownExpires != null && this.wellKnownExpires.isBefore(now)) {
            // configuration is still fresh
            return;
        }

        // Get the well-known configuration from the specified URL
        try {
            URL url = new URL(wellKnownOpenIDConfigurationUrl);
            HttpRequest request = httpTransport.createRequestFactory().buildGetRequest(new GenericUrl(url));

            com.google.api.client.http.HttpResponse response = request.execute();
            WellKnownOpenIDConfigurationResponse config = GsonFactory.getDefaultInstance()
                    .fromInputStream(
                            response.getContent(),
                            Charset.defaultCharset(),
                            WellKnownOpenIDConfigurationResponse.class);

            this.authorizationServerUrl = Util.fixNull(config.getAuthorizationEndpoint(), this.authorizationServerUrl);
            this.tokenServerUrl = Util.fixNull(config.getTokenEndpoint(), this.tokenServerUrl);
            this.jwksServerUrl = Util.fixNull(config.getJwksUri(), this.jwksServerUrl);
            this.tokenAuthMethod = Util.fixNull(config.getPreferredTokenAuthMethod(), this.tokenAuthMethod);
            this.userInfoServerUrl = Util.fixNull(config.getUserinfoEndpoint(), this.userInfoServerUrl);
            if (config.getScopesSupported() != null) {
                this.setScopes(StringUtils.join(config.getScopesSupported(), " "));
            }
            this.applyOverrideScopes();
            this.endSessionEndpoint = Util.fixNull(config.getEndSessionEndpoint(), this.endSessionEndpoint);

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

    /** Parse headers to determine expiration date
     */
    private void setWellKnownExpires(HttpHeaders headers) {
        String expires = Util.fixEmptyAndTrim(headers.getExpires());
        // expires 0 means no cache
        // we could (should?) have a look at Cache-Control header and max-age but for simplicity
        // we can just leave it default TTL 1h refresh which sounds reasonable for such file
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

    @DataBoundSetter
    public void setWellKnownOpenIDConfigurationUrl(String wellKnownOpenIDConfigurationUrl) {
        if (this.isAutoConfigure()
                || (this.automanualconfigure.isEmpty()
                        && !Util.fixNull(wellKnownOpenIDConfigurationUrl).isEmpty())) {
            this.automanualconfigure = "auto";
            this.wellKnownOpenIDConfigurationUrl = wellKnownOpenIDConfigurationUrl;
            this.loadWellKnownOpenIDConfigurationUrl();
        } else {
            this.automanualconfigure = "manual";
            this.wellKnownOpenIDConfigurationUrl = null;
        }
    }

    private void applyOverrideScopes() {
        if (!"auto".equals(this.automanualconfigure) || this.overrideScopes == null) {
            // only applies in "auto" mode when overrideScopes defined
            return;
        }
        if (this.scopes == null) {
            this.scopes = overrideScopes;
            return;
        }
        // keep only scopes that are in overrideScopes
        HashSet<String> scopesSet =
                new HashSet<>(Arrays.asList(this.scopes.trim().split("\\s+")));
        scopesSet.retainAll(Arrays.asList(this.overrideScopes.trim().split("\\s+")));
        this.setScopes(StringUtils.join(scopesSet, " "));
    }

    @DataBoundSetter
    public void setUserNameField(String userNameField) {
        this.userNameField = Util.fixNull(Util.fixEmptyAndTrim(userNameField), "sub");
        this.userNameFieldExpr = compileJMESPath(this.userNameField, "user name field");
    }

    @DataBoundSetter
    public void setTokenFieldToCheckKey(String tokenFieldToCheckKey) {
        this.tokenFieldToCheckKey = Util.fixEmptyAndTrim(tokenFieldToCheckKey);
        this.tokenFieldToCheckExpr = compileJMESPath(this.tokenFieldToCheckKey, "token field to check");
    }

    @DataBoundSetter
    public void setTokenFieldToCheckValue(String tokenFieldToCheckValue) {
        this.tokenFieldToCheckValue = Util.fixEmptyAndTrim(tokenFieldToCheckValue);
    }

    @DataBoundSetter
    public void setFullNameFieldName(String fullNameFieldName) {
        this.fullNameFieldName = Util.fixEmptyAndTrim(fullNameFieldName);
        this.fullNameFieldExpr = compileJMESPath(this.fullNameFieldName, "full name field");
    }

    @DataBoundSetter
    public void setEmailFieldName(String emailFieldName) {
        this.emailFieldName = Util.fixEmptyAndTrim(emailFieldName);
        this.emailFieldExpr = compileJMESPath(this.emailFieldName, "email field");
    }

    protected static Expression<Object> compileJMESPath(String str, String logComment) {
        if (str == null) {
            return null;
        }

        try {
            Expression<Object> expr = JMESPATH.compile(str);
            if (expr == null && logComment != null) {
                LOGGER.warning(logComment + " with config '" + str + "' is an invalid JMESPath expression ");
            }
            return expr;
        } catch (RuntimeException e) {
            if (logComment != null) {
                LOGGER.warning(logComment + " config failed " + e.toString());
            }
        }
        return null;
    }

    private Object applyJMESPath(Expression<Object> expression, GenericJson json) {
        return expression.search(json);
    }

    @DataBoundSetter
    public void setGroupsFieldName(String groupsFieldName) {
        this.groupsFieldName = Util.fixEmptyAndTrim(groupsFieldName);
        this.groupsFieldExpr = this.compileJMESPath(groupsFieldName, "groups field");
    }

    // Not a DataBoundSetter - set in constructor
    public void setScopes(String scopes) {
        this.scopes = Util.fixEmptyAndTrim(scopes);
    }

    @DataBoundSetter
    public void setLogoutFromOpenidProvider(boolean logoutFromOpenidProvider) {
        this.logoutFromOpenidProvider = logoutFromOpenidProvider;
    }

    @DataBoundSetter
    public void setPostLogoutRedirectUrl(String postLogoutRedirectUrl) {
        this.postLogoutRedirectUrl = Util.fixEmptyAndTrim(postLogoutRedirectUrl);
    }

    @DataBoundSetter
    public void setEscapeHatchEnabled(boolean escapeHatchEnabled) {
        this.escapeHatchEnabled = escapeHatchEnabled;
    }

    @DataBoundSetter
    public void setEscapeHatchUsername(String escapeHatchUsername) {
        this.escapeHatchUsername = Util.fixEmptyAndTrim(escapeHatchUsername);
    }

    @DataBoundSetter
    public void setEscapeHatchSecret(Secret escapeHatchSecret) {
        if (escapeHatchSecret != null) {
            // ensure escapeHatchSecret is BCrypt hash
            String escapeHatchString = Secret.toString(escapeHatchSecret);

            final Pattern BCryptPattern = Pattern.compile("\\A\\$[^$]+\\$\\d+\\$[./0-9A-Za-z]{53}");
            if (!BCryptPattern.matcher(escapeHatchString).matches()) {
                this.escapeHatchSecret = Secret.fromString(BCrypt.hashpw(escapeHatchString, BCrypt.gensalt()));
                return;
            }
        }
        this.escapeHatchSecret = escapeHatchSecret;
    }

    protected boolean checkEscapeHatch(String username, String password) {
        final boolean isUsernameMatch = username.equals(this.escapeHatchUsername);
        final boolean isPasswordMatch = BCrypt.checkpw(password, Secret.toString(this.escapeHatchSecret));
        return isUsernameMatch & isPasswordMatch;
    }

    @DataBoundSetter
    public void setEscapeHatchGroup(String escapeHatchGroup) {
        this.escapeHatchGroup = Util.fixEmptyAndTrim(escapeHatchGroup);
    }

    @DataBoundSetter
    public void setOverrideScopesDefined(boolean overrideScopesDefined) {
        if (overrideScopesDefined) {
            this.overrideScopesDefined = Boolean.TRUE;
        } else {
            this.overrideScopesDefined = Boolean.FALSE;
            this.overrideScopes = null;
            this.applyOverrideScopes();
        }
    }

    @DataBoundSetter
    public void setOverrideScopes(String overrideScopes) {
        if (this.overrideScopesDefined == null || this.overrideScopesDefined) {
            this.overrideScopes = Util.fixEmptyAndTrim(overrideScopes);
            this.applyOverrideScopes();
        }
    }

    @DataBoundSetter
    public void setRootURLFromRequest(boolean rootURLFromRequest) {
        this.rootURLFromRequest = rootURLFromRequest;
    }

    @DataBoundSetter
    public void setSendScopesInTokenRequest(boolean sendScopesInTokenRequest) {
        this.sendScopesInTokenRequest = sendScopesInTokenRequest;
    }

    @DataBoundSetter
    public void setPkceEnabled(boolean pkceEnabled) {
        this.pkceEnabled = pkceEnabled;
    }

    @DataBoundSetter
    public void setDisableTokenVerification(boolean disableTokenVerification) {
        this. disableTokenVerification = disableTokenVerification;
    }

    @DataBoundSetter
    public void setNonceDisabled(boolean nonceDisabled) {
        this.nonceDisabled = nonceDisabled;
    }

    @Override
    public String getLoginUrl() {
        // Login begins with our doCommenceLogin(String,String) method
        return "securityRealm/commenceLogin";
    }

    @Override
    public String getAuthenticationGatewayUrl() {
        return "securityRealm/escapeHatch";
    }

    /*
     * Acegi has this notion that first an {@link org.acegisecurity.Authentication} object is created
     * by collecting user information and then the act of authentication is done
     * later (by {@link org.acegisecurity.AuthenticationManager}) to verify it. But in case of OpenID,
     * we create an {@link org.acegisecurity.Authentication} only after we verified the user identity,
     * so {@link org.acegisecurity.AuthenticationManager} becomes no-op.
     */
    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                new AuthenticationManager() {
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        if (authentication instanceof AnonymousAuthenticationToken) return authentication;

                        if (authentication instanceof UsernamePasswordAuthenticationToken && escapeHatchEnabled) {
                            randomWait(); // to slowdown brute forcing
                            if (checkEscapeHatch(
                                    authentication.getPrincipal().toString(),
                                    authentication.getCredentials().toString())) {
                                List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
                                grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
                                if (isNotBlank(escapeHatchGroup)) {
                                    grantedAuthorities.add(new SimpleGrantedAuthority(escapeHatchGroup));
                                }
                                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                                        escapeHatchUsername, "", grantedAuthorities);
                                SecurityContextHolder.getContext().setAuthentication(token);
                                OicUserDetails userDetails =
                                        new OicUserDetails(escapeHatchUsername, grantedAuthorities);
                                SecurityListener.fireAuthenticated2(userDetails);
                                return token;
                            } else {
                                throw new BadCredentialsException("Wrong username and password: " + authentication);
                            }
                        }
                        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                    }
                },
                new UserDetailsService() {

                    @Override
                    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                        // Retrieve the OicUserProperty to get the list of groups that has to be set in the
                        // OicUserDetails object.
                        LOGGER.fine("loadUserByUsername in createSecurityComponents called, username: " + username);
                        User u = User.get(username, false, Collections.emptyMap());
                        if (u == null) {
                            LOGGER.fine("loadUserByUsername in createSecurityComponents called, no user '" + username
                                    + "' found");
                            throw new UsernameNotFoundException(username);
                        }
                        LOGGER.fine("loadUserByUsername in createSecurityComponents called, user: " + u);
                        OicUserProperty oicProp = u.getProperty(OicUserProperty.class);
                        List<GrantedAuthority> auths = new ArrayList<>();
                        if (oicProp != null) {
                            auths = oicProp.getAuthoritiesAsGrantedAuthorities();
                            LOGGER.fine(
                                    "loadUserByUsername in createSecurityComponents called, oic prop found with username '"
                                            + oicProp.getUserName() + "', auths size: " + auths.size());
                        }
                        return new OicUserDetails(username, auths);
                    }
                });
    }

    /** Build authorization code flow
     */
    protected AuthorizationCodeFlow buildAuthorizationCodeFlow() {
        AccessMethod tokenAccessMethod = BearerToken.queryParameterAccessMethod();
        HttpExecuteInterceptor authInterceptor =
                new ClientParametersAuthentication(clientId, Secret.toString(clientSecret));
        if (TokenAuthMethod.client_secret_basic.equals(tokenAuthMethod)) {
            tokenAccessMethod = BearerToken.authorizationHeaderAccessMethod();
            authInterceptor = new BasicAuthentication(clientId, Secret.toString(clientSecret));
        }
        AuthorizationCodeFlow.Builder builder = new AuthorizationCodeFlow.Builder(
                        tokenAccessMethod,
                        httpTransport,
                        GsonFactory.getDefaultInstance(),
                        new GenericUrl(tokenServerUrl),
                        authInterceptor,
                        clientId,
                        authorizationServerUrl)
                .setScopes(Arrays.asList(this.getScopes()));

        return builder.build();
    }

    protected String getValidRedirectUrl(String url) {
        final String rootUrl = getRootUrl();
        if (url != null && !url.isEmpty()) {
            try {
                final String redirectUrl = new URL(new URL(rootUrl), url).toString();
                // check redirect url stays within rootUrl
                if (redirectUrl.startsWith(rootUrl)) {
                    return redirectUrl;
                }
            } catch (MalformedURLException e) {
                // Invalid URL, will return root URL
            }
        }
        return rootUrl;
    }

    /**
     * Handles the the securityRealm/commenceLogin resource and sends the user off to the IdP
     * @param from the relative URL to the page that the user has just come from
     * @param referer the HTTP referer header (where to redirect the user back to after login has finished)
     * @return an {@link HttpResponse} object
     */
    @Restricted(DoNotUse.class) // stapler only
    public HttpResponse doCommenceLogin(@QueryParameter String from, @Header("Referer") final String referer) {
        // reload config if needed
        loadWellKnownOpenIDConfigurationUrl();

        final String redirectOnFinish = getValidRedirectUrl(from != null ? from : referer);

        return new OicSession(from, buildOAuthRedirectUrl()) {
            @Override
            public HttpResponse onSuccess(String authorizationCode, AuthorizationCodeFlow flow) {
                try {
                    AuthorizationCodeTokenRequest tokenRequest = flow.newTokenRequest(authorizationCode)
                            .setRedirectUri(buildOAuthRedirectUrl())
                            .setResponseClass(OicTokenResponse.class);
                    if (this.pkceVerifierCode != null) {
                        tokenRequest.set("code_verifier", this.pkceVerifierCode);
                    }
                    if (!sendScopesInTokenRequest) {
                        tokenRequest.setScopes(Collections.emptyList());
                    }

                    OicTokenResponse response = (OicTokenResponse) tokenRequest.execute();

                    if (response.getIdToken() == null) {
                        return HttpResponses.errorWithoutStack(500, Messages.OicSecurityRealm_NoIdTokenInResponse());
                    }
                    IdToken idToken;
                    try {
                         idToken = response.parseIdToken();
                    } catch(IllegalArgumentException e) {
                        return HttpResponses.errorWithoutStack(403, Messages.OicSecurityRealm_IdTokenParseError());
                    }
                    if (!validateIdToken(idToken)) {
                        return HttpResponses.errorWithoutStack(401, "Unauthorized");
                    }
                    if (!isNonceDisabled() && !validateNonce(idToken)) {
                        return HttpResponses.errorWithoutStack(401, "Unauthorized");
                    }

                    if (failedCheckOfTokenField(idToken)) {
                        return HttpResponses.errorWithoutStack(401, "Unauthorized");
                    }

                    this.setIdToken(response.getIdToken());

                    GenericJson userInfo = null;
                    if (!Strings.isNullOrEmpty(userInfoServerUrl)) {
                        userInfo = getUserInfo(flow, response.getAccessToken());
                        if (userInfo == null) {
                            return HttpResponses.errorWithoutStack(401, "Unauthorized");
                        }
                    }

                    String username = determineStringField(userNameFieldExpr, idToken, userInfo);
                    if (username == null) {
                        return HttpResponses.error(500, Messages.OicSecurityRealm_UsernameNotFound(userNameField));
                    }

                    flow.createAndStoreCredential(response, null);

                    loginAndSetUserData(username.toString(), idToken, userInfo);

                    return new HttpRedirect(redirectOnFinish);

                } catch (IOException e) {
                    return HttpResponses.error(500, Messages.OicSecurityRealm_TokenRequestFailure(e));
                }
            }
        }.withNonceDisabled(isNonceDisabled())
        .withPkceEnabled(isPkceEnabled())
        .commenceLogin(buildAuthorizationCodeFlow());
    }

    /** Create OicJsonWebTokenVerifier if needed */
    private OicJsonWebTokenVerifier getJwksVerifier() {
        if (isDisableTokenVerification()) {
            return null;
        }
        if (jwtVerifier == null) {
            jwtVerifier = new OicJsonWebTokenVerifier(
                    jwksServerUrl,
                    new OicJsonWebTokenVerifier.Builder()
                        .setHttpTransportFactory(new HttpTransportFactory() {
                            @Override
                            public HttpTransport create() {
                                return httpTransport;
                            }
                        }));
        }
        return jwtVerifier;
    }

    /** Validate UserInfo signature if available */
    private boolean validateUserInfo(JsonWebSignature userinfo)  throws IOException {
        OicJsonWebTokenVerifier verifier = getJwksVerifier();
        if (verifier == null) {
            return true;
        }
        return verifier.verifyUserInfo(userinfo);
    }

    /** Validate IdToken signature if available */
    private boolean validateIdToken(IdToken idtoken) throws IOException {
        OicJsonWebTokenVerifier verifier = getJwksVerifier();
        if (verifier == null) {
            return true;
        }
        return verifier.verifyIdToken(idtoken);
    }

    @SuppressFBWarnings(
            value = "DMI_RANDOM_USED_ONLY_ONCE",
            justification = "False positive in spotbug about DMI_RANDOM_USED_ONLY_ONCE")
    // see https://github.com/spotbugs/spotbugs/issues/1539
    private void randomWait() {
        try {
            Thread.sleep(1000 + RANDOM.nextInt(1000));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private GenericJson getUserInfo(final AuthorizationCodeFlow flow, final String accessToken) throws IOException {
        HttpRequestFactory requestFactory = flow.getTransport().createRequestFactory(new HttpRequestInitializer() {
            @Override
            public void initialize(HttpRequest request) throws IOException {
                request.getHeaders().setAuthorization("Bearer " + accessToken);
            }
        });
        HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(userInfoServerUrl));
        request.setThrowExceptionOnExecuteError(false);
        com.google.api.client.http.HttpResponse response = request.execute();
        if (response.isSuccessStatusCode()) {
            if (response.getHeaders().getContentType().contains("application/jwt")) {
                String token = response.parseAsString();
                JsonWebSignature jws = JsonWebSignature.parse(flow.getJsonFactory(), token);
                if (!validateUserInfo(jws)) {
                    return null;
                }
                return jws.getPayload();
            }

            JsonObjectParser parser = new JsonObjectParser(flow.getJsonFactory());
            return parser.parseAndClose(response.getContent(), response.getContentCharset(), GenericJson.class);
        }
        throw new HttpResponseException(response);
    }

    private boolean failedCheckOfTokenField(IdToken idToken) {
        if (tokenFieldToCheckKey == null || tokenFieldToCheckValue == null) {
            return false;
        }

        if (idToken == null) {
            return true;
        }

        String value = getStringField(idToken.getPayload(), tokenFieldToCheckExpr);
        if (value == null) {
            return true;
        }

        return !tokenFieldToCheckValue.equals(value);
    }

    private UsernamePasswordAuthenticationToken loginAndSetUserData(
            String userName, IdToken idToken, GenericJson userInfo) throws IOException {

        List<GrantedAuthority> grantedAuthorities = determineAuthorities(idToken, userInfo);
        if (LOGGER.isLoggable(Level.FINEST)) {
            StringBuilder grantedAuthoritiesAsString = new StringBuilder(userName);
            grantedAuthoritiesAsString.append(" (");
            for (GrantedAuthority grantedAuthority : grantedAuthorities) {
                grantedAuthoritiesAsString.append(" ").append(grantedAuthority.getAuthority());
            }
            grantedAuthoritiesAsString.append(" )");
            LOGGER.finest("GrantedAuthorities:" + grantedAuthoritiesAsString);
        }

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(userName, "", grantedAuthorities);

        SecurityContextHolder.getContext().setAuthentication(token);

        User user = User.get2(token);
        if (user == null) {
            // should not happen
            throw new IOException("Cannot set OIDC property on anonymous user");
        }
        // Store the list of groups in a OicUserProperty so it can be retrieved later for the UserDetails object.
        user.addProperty(new OicUserProperty(userName, grantedAuthorities));

        String email = determineStringField(emailFieldExpr, idToken, userInfo);
        if (email != null) {
            user.addProperty(new Mailer.UserProperty(email));
        }

        String fullName = determineStringField(fullNameFieldExpr, idToken, userInfo);
        if (fullName != null) {
            user.setFullName(fullName);
        }

        OicUserDetails userDetails = new OicUserDetails(userName, grantedAuthorities);
        SecurityListener.fireAuthenticated2(userDetails);

        return token;
    }

    private String determineStringField(Expression<Object> fieldExpr, IdToken idToken, GenericJson userInfo) {
        if (fieldExpr != null) {
            if (userInfo != null) {
                Object field = fieldExpr.search(userInfo);
                if (field != null && field instanceof String) {
                    String fieldValue = Util.fixEmptyAndTrim((String) field);
                    if (fieldValue != null) {
                        return fieldValue;
                    }
                }
            }
            if (idToken != null) {
                String fieldValue = Util.fixEmptyAndTrim(getStringField(idToken.getPayload(), fieldExpr));
                if (fieldValue != null) {
                    return fieldValue;
                }
            }
        }
        return null;
    }

    protected String getStringField(Object object, Expression<Object> fieldExpr) {
        if (object != null && fieldExpr != null) {
            Object value = fieldExpr.search(object);
            if ((value != null) && !(value instanceof Map) && !(value instanceof List)) {
                return String.valueOf(value);
            }
        }
        return null;
    }

    private List<GrantedAuthority> determineAuthorities(IdToken idToken, GenericJson userInfo) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
        if (this.groupsFieldExpr == null) {
            if (this.groupsFieldName == null) {
                LOGGER.fine("Not adding groups because groupsFieldName is not set. groupsFieldName=" + groupsFieldName);
            } else {
                LOGGER.fine("Not adding groups because groupsFieldName is invalid. groupsFieldName=" + groupsFieldName);
            }
            return grantedAuthorities;
        }

        Object groupsObject = null;

        // userInfo has precedence when available
        if (userInfo != null) {
            groupsObject = this.groupsFieldExpr.search(userInfo);
        }
        if (groupsObject == null && idToken != null) {
            groupsObject = this.groupsFieldExpr.search(idToken.getPayload());
        }
        if (groupsObject == null) {
            LOGGER.warning("idToken and userInfo did not contain group field name: " + this.groupsFieldName);
            return grantedAuthorities;
        }

        List<String> groupNames = ensureString(groupsObject);
        if (groupNames.isEmpty()) {
            LOGGER.warning("Could not identify groups in " + groupsFieldName + "=" + groupsObject.toString());
            return grantedAuthorities;
        }
        LOGGER.fine("Number of groups in groupNames: " + groupNames.size());

        for (String groupName : groupNames) {
            LOGGER.fine("Adding group from UserInfo: " + groupName);
            grantedAuthorities.add(new SimpleGrantedAuthority(groupName));
        }

        return grantedAuthorities;
    }

    /** Ensure group field object returns is string or list of string
     */
    private List<String> ensureString(Object field) {
        if (field == null || Data.isNull(field)) {
            LOGGER.warning("userInfo did not contain a valid group field content, got null");
            return Collections.<String>emptyList();
        } else if (field instanceof String) {
            // if its a String, the original value was not a json array.
            // We try to convert the string to list based on comma while ignoring whitespaces and square brackets.
            // Example value "[demo-user-group, demo-test-group, demo-admin-group]"
            String sField = (String) field;
            String[] rawFields = sField.split("[\\s\\[\\],]");
            List<String> result = new ArrayList<>();
            for (String rawField : rawFields) {
                if (rawField != null && !rawField.isEmpty()) {
                    result.add(rawField);
                }
            }
            return result;
        } else if (field instanceof ArrayList) {
            List<String> result = new ArrayList<>();
            List<Object> groups = (List<Object>) field;
            for (Object group : groups) {
                if (group instanceof String) {
                    result.add(group.toString());
                } else if (group instanceof ArrayMap) {
                    // if its a Map, we use the nestedGroupFieldName to grab the groups
                    Map<String, String> groupMap = (Map<String, String>) group;
                    if (nestedGroupFieldName != null && groupMap.keySet().contains(nestedGroupFieldName)) {
                        result.add(groupMap.get(nestedGroupFieldName));
                    }
                }
            }
            return result;
        } else {
            try {
                return (List<String>) field;
            } catch (ClassCastException e) {
                LOGGER.warning("userInfo did not contain a valid group field content, got: "
                        + field.getClass().getSimpleName());
                return Collections.<String>emptyList();
            }
        }
    }

    @Restricted(DoNotUse.class) // stapler only
    public void doLogout(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        OicSession oicSession = OicSession.getCurrent();
        if (oicSession != null) {
            // session will be invalidated but we still need this data for our redirect.
            req.setAttribute(ID_TOKEN_REQUEST_ATTRIBUTE, oicSession.getIdToken());
            req.setAttribute(STATE_REQUEST_ATTRIBUTE, oicSession.getState());
        }
        super.doLogout(req, rsp);
    }

    @Override
    public String getPostLogOutUrl2(StaplerRequest req, Authentication auth) {
        if (this.logoutFromOpenidProvider && !Strings.isNullOrEmpty(this.endSessionEndpoint)) {
            StringBuilder openidLogoutEndpoint = new StringBuilder(this.endSessionEndpoint);
            openidLogoutEndpoint.append("?id_token_hint=").append(req.getAttribute(ID_TOKEN_REQUEST_ATTRIBUTE));
            openidLogoutEndpoint.append("&state=").append(req.getAttribute(STATE_REQUEST_ATTRIBUTE));

            if (this.postLogoutRedirectUrl != null) {
                try {
                    openidLogoutEndpoint
                            .append("&post_logout_redirect_uri=")
                            .append(URLEncoder.encode(this.postLogoutRedirectUrl, "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
            }
            return openidLogoutEndpoint.toString();
        }

        return getFinalLogoutUrl(req, auth);
    }

    private String getFinalLogoutUrl(StaplerRequest req, Authentication auth) {
        if (Jenkins.get().hasPermission(Jenkins.READ)) {
            return super.getPostLogOutUrl2(req, auth);
        }
        return req.getContextPath() + "/" + OicLogoutAction.POST_LOGOUT_URL;
    }

    private String getRootUrl() {
        if (rootURLFromRequest) {
            return Jenkins.get().getRootUrlFromRequest();
        } else {
            return Jenkins.get().getRootUrl();
        }
    }

    private String buildOAuthRedirectUrl() throws NullPointerException {
        String rootUrl = getRootUrl();
        if (rootUrl == null) {
            throw new NullPointerException("Jenkins root url should not be null");
        } else {
            return rootUrl + "securityRealm/finishLogin";
        }
    }

    /**
     * This is where the user comes back to at the end of the OpenID redirect ping-pong.
     * @param request The user's request
     * @return an HttpResponse
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        OicSession currentSession = OicSession.getCurrent();
        if (currentSession == null) {
            LOGGER.fine("No session to resume (perhaps jenkins was restarted?)");
            return HttpResponses.errorWithoutStack(401, "Unauthorized");
        }
        return currentSession.finishLogin(request, buildAuthorizationCodeFlow());
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        public boolean isAuto() {
            SecurityRealm realm = Jenkins.get().getSecurityRealm();
            return realm instanceof OicSecurityRealm
                    && StringUtils.isNotBlank(((OicSecurityRealm) realm).getWellKnownOpenIDConfigurationUrl());
        }

        public boolean isManual() {
            return Jenkins.get().getSecurityRealm() instanceof OicSecurityRealm && !isAuto();
        }

        public String getDisplayName() {
            return Messages.OicSecurityRealm_DisplayName();
        }

        @RequirePOST
        public FormValidation doCheckClientId(@QueryParameter String clientId) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(clientId) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_ClientIdRequired());
            }
            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doCheckClientSecret(@QueryParameter String clientSecret) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(clientSecret) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_ClientSecretRequired());
            }
            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doCheckWellKnownOpenIDConfigurationUrl(
                @QueryParameter String wellKnownOpenIDConfigurationUrl,
                @QueryParameter boolean disableSslVerification) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            try {
                URL url = new URL(wellKnownOpenIDConfigurationUrl);
                HttpRequest request = constructHttpTransport(disableSslVerification)
                        .createRequestFactory()
                        .buildGetRequest(new GenericUrl(url));
                com.google.api.client.http.HttpResponse response = request.execute();

                // Try to parse the response. If it's not valid, a JsonParseException will be thrown indicating
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

        @RequirePOST
        public FormValidation doCheckTokenServerUrl(@QueryParameter String tokenServerUrl) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(tokenServerUrl) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_TokenServerURLKeyRequired());
            }
            try {
                new URL(tokenServerUrl);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @RequirePOST
        public FormValidation doCheckJwksServerUrl(@QueryParameter String jwksServerUrl) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(jwksServerUrl) == null) {
                return FormValidation.ok();
            }
            try {
                new URL(jwksServerUrl);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @RequirePOST
        public FormValidation doCheckTokenAuthMethod(@QueryParameter String tokenAuthMethod) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(tokenAuthMethod) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_TokenAuthMethodRequired());
            }
            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doCheckAuthorizationServerUrl(@QueryParameter String authorizationServerUrl) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (authorizationServerUrl == null) {
                return FormValidation.error(Messages.OicSecurityRealm_TokenServerURLKeyRequired());
            }
            try {
                new URL(authorizationServerUrl);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @RequirePOST
        public FormValidation doCheckScopes(@QueryParameter String scopes) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(scopes) == null) {
                return FormValidation.ok(Messages.OicSecurityRealm_UsingDefaultScopes());
            }
            if (!scopes.toLowerCase().contains("openid")) {
                return FormValidation.warning(Messages.OicSecurityRealm_RUSureOpenIdNotInScope());
            }
            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doCheckOverrideScopes(@QueryParameter String overrideScopes) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(overrideScopes) == null) {
                return FormValidation.ok(Messages.OicSecurityRealm_UsingDefaultScopes());
            }
            if (!overrideScopes.toLowerCase().contains("openid")) {
                return FormValidation.warning(Messages.OicSecurityRealm_RUSureOpenIdNotInScope());
            }
            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doCheckEndSessionEndpoint(@QueryParameter String endSessionEndpoint) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(endSessionEndpoint) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_EndSessionURLKeyRequired());
            }
            try {
                new URL(endSessionEndpoint);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @RequirePOST
        public FormValidation doCheckPostLogoutRedirectUrl(@QueryParameter String postLogoutRedirectUrl) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(postLogoutRedirectUrl) != null) {
                try {
                    new URL(postLogoutRedirectUrl);
                    return FormValidation.ok();
                } catch (MalformedURLException e) {
                    return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
                }
            }

            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doCheckUserNameField(@QueryParameter String userNameField) {
            return this.doCheckFieldName(
                    userNameField, FormValidation.ok(Messages.OicSecurityRealm_UsingDefaultUsername()));
        }

        @RequirePOST
        public FormValidation doCheckFullNameFieldName(@QueryParameter String fullNameFieldName) {
            return this.doCheckFieldName(fullNameFieldName, FormValidation.ok());
        }

        @RequirePOST
        public FormValidation doCheckEmailFieldName(@QueryParameter String emailFieldName) {
            return this.doCheckFieldName(emailFieldName, FormValidation.ok());
        }

        @RequirePOST
        public FormValidation doCheckGroupsFieldName(@QueryParameter String groupsFieldName) {
            return this.doCheckFieldName(groupsFieldName, FormValidation.ok());
        }

        @RequirePOST
        public FormValidation doCheckTokenFieldToCheckKey(@QueryParameter String tokenFieldToCheckKey) {
            return this.doCheckFieldName(tokenFieldToCheckKey, FormValidation.ok());
        }

        // method to check fieldName matches JMESPath format
        private FormValidation doCheckFieldName(String fieldName, FormValidation validIfNull) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(fieldName) == null) {
                return validIfNull;
            }
            if (OicSecurityRealm.compileJMESPath(fieldName, null) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_InvalidFieldName());
            }
            return FormValidation.ok();
        }
    }
}
