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
import com.google.api.client.auth.oauth2.RefreshTokenRequest;
import com.google.api.client.auth.oauth2.TokenErrorResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.auth.openidconnect.HttpTransportFactory;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpExecuteInterceptor;
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
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import hudson.model.User;
import hudson.security.ChainedServletFilter;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.burt.jmespath.Expression;
import io.burt.jmespath.JmesPath;
import io.burt.jmespath.RuntimeConfiguration;
import io.burt.jmespath.jcf.JcfRuntime;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import jenkins.security.SecurityListener;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
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
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.util.Assert;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * Login with OpenID Connect / OAuth 2
 *
 * @author Michael Bischoff
 * @author Steve Arch
 */
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

    /** @deprecated see {@link OicServerWellKnownConfiguration#getWellKnownOpenIDConfigurationUrl()} */
    @Deprecated
    private transient String wellKnownOpenIDConfigurationUrl;

    /** @deprecated see {@link OicServerConfiguration#getTokenServerUrl()} */
    @Deprecated
    private transient String tokenServerUrl;

    /** @deprecated see {@link OicServerConfiguration#getJwksServerUrl()} */
    @Deprecated
    private transient String jwksServerUrl;

    /** @deprecated see {@link OicServerConfiguration#getTokenAuthMethod()} */
    @Deprecated
    private transient TokenAuthMethod tokenAuthMethod;

    /** @deprecated see {@link OicServerConfiguration#getAuthorizationServerUrl()} */
    @Deprecated
    private transient String authorizationServerUrl;

    /** @deprecated see {@link OicServerConfiguration#getUserInfoServerUrl()} */
    @Deprecated
    private transient String userInfoServerUrl;

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

    /** @deprecated see {@link OicServerConfiguration#getScopes()} */
    @Deprecated
    private transient String scopes = null;

    private final boolean disableSslVerification;
    private boolean logoutFromOpenidProvider = true;

    /** @deprecated see {@link OicServerConfiguration#getEndSessionUrl()} */
    @Deprecated
    private transient String endSessionEndpoint = null;

    private String postLogoutRedirectUrl;
    private boolean escapeHatchEnabled = false;
    private String escapeHatchUsername = null;
    private Secret escapeHatchSecret = null;
    private String escapeHatchGroup = null;

    @Deprecated
    /** @deprecated with no replacement.  See sub classes of {@link OicServerConfiguration} */
    private transient String automanualconfigure = null;

    @Deprecated
    /** @deprecated see {@link OicServerWellKnownConfiguration#isUseRefreshTokens()} */
    private transient boolean useRefreshTokens = false;

    private OicServerConfiguration serverConfiguration;

    /** @deprecated see {@link OicServerWellKnownConfiguration#getScopes()} */
    @Deprecated
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

    /** Flag to disable token expiration check
     */
    private boolean tokenExpirationCheckDisabled = false;

    /** Flag to enable traditional Jenkins API token based access (no OicSession needed)
     */
    private boolean allowTokenAccessWithoutOicSession = false;

    /** Additional number of seconds to add to token expiration
     */
    private Long allowedTokenExpirationClockSkewSeconds = 60L;

    /** old field that had an '/' implicitly added at the end,
     * transient because we no longer want to have this value stored
     * but it's still needed for backwards compatibility */
    @Deprecated
    private transient String endSessionUrl;

    /** Verification of IdToken and UserInfo (in jwt case)
     */
    private transient OicJsonWebTokenVerifier jwtVerifier;

    private transient HttpTransport httpTransport = null;

    /** Random generator needed for robust random wait
     */
    private static final Random RANDOM = new Random();

    /** Clock used for token expiration check
     */
    private static final Clock CLOCK = Clock.systemUTC();

    /** Runtime context to compile JMESPath
     */
    private static final JmesPath<Object> JMESPATH = new JcfRuntime(
            new RuntimeConfiguration.Builder().withSilentTypeErrors(true).build());

    @DataBoundConstructor
    public OicSecurityRealm(
            String clientId,
            Secret clientSecret,
            OicServerConfiguration serverConfiguration,
            Boolean disableSslVerification)
            throws IOException {
        // Needed in DataBoundSetter
        this.disableSslVerification = Util.fixNull(disableSslVerification, Boolean.FALSE);
        this.httpTransport = constructHttpTransport(this.disableSslVerification);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.serverConfiguration = serverConfiguration;
    }

    @SuppressWarnings("deprecated")
    protected Object readResolve() throws ObjectStreamException {
        if (httpTransport == null) {
            httpTransport = constructHttpTransport(isDisableSslVerification());
        }
        if (!Strings.isNullOrEmpty(endSessionUrl)) {
            this.endSessionEndpoint = endSessionUrl + "/";
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
        try {
            if (automanualconfigure != null) {
                if ("auto".equals(automanualconfigure)) {
                    OicServerWellKnownConfiguration conf =
                            new OicServerWellKnownConfiguration(wellKnownOpenIDConfigurationUrl);
                    conf.setScopesOverride(this.overrideScopes);
                    serverConfiguration = conf;
                } else {
                    OicServerManualConfiguration conf =
                            new OicServerManualConfiguration(tokenServerUrl, authorizationServerUrl);
                    if (tokenAuthMethod != null) {
                        conf.setTokenAuthMethod(tokenAuthMethod);
                    }
                    conf.setEndSessionUrl(endSessionEndpoint);
                    conf.setJwksServerUrl(jwksServerUrl);
                    conf.setScopes(scopes != null ? scopes : "openid email");
                    conf.setUseRefreshTokens(useRefreshTokens);
                    conf.setUserInfoServerUrl(userInfoServerUrl);
                    serverConfiguration = conf;
                }
            }
        } catch (FormException e) {
            // FormException does not override toString() so looses info on the fields set and the message may not have
            // context
            // extract if into a better message until this is fixed.
            ObjectStreamException ose = new InvalidObjectException(e.getFormField() + ": " + e.getMessage());
            ose.initCause(e);
            throw ose;
        }
        return this;
    }

    static HttpTransport constructHttpTransport(boolean disableSslVerification) {
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

    /**
     * Obtain the shared HttpTransport.
     * The transport may be invalidated if the realm is saved so should not be cached.
     * @return the shared {@code HttpTransport}.
     */
    @Restricted(NoExternalUse.class)
    HttpTransport getHttpTransport() {
        return httpTransport;
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret == null ? Secret.fromString(NO_SECRET) : clientSecret;
    }

    @Restricted(NoExternalUse.class) // jelly access
    public OicServerConfiguration getServerConfiguration() {
        return serverConfiguration;
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

    public boolean isDisableSslVerification() {
        return disableSslVerification;
    }

    public boolean isLogoutFromOpenidProvider() {
        return logoutFromOpenidProvider;
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

    public boolean isTokenExpirationCheckDisabled() {
        return tokenExpirationCheckDisabled;
    }

    public boolean isAllowTokenAccessWithoutOicSession() {
        return allowTokenAccessWithoutOicSession;
    }

    public Long getAllowedTokenExpirationClockSkewSeconds() {
        return allowedTokenExpirationClockSkewSeconds;
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
        this.disableTokenVerification = disableTokenVerification;
    }

    @DataBoundSetter
    public void setNonceDisabled(boolean nonceDisabled) {
        this.nonceDisabled = nonceDisabled;
    }

    @DataBoundSetter
    public void setTokenExpirationCheckDisabled(boolean tokenExpirationCheckDisabled) {
        this.tokenExpirationCheckDisabled = tokenExpirationCheckDisabled;
    }

    @DataBoundSetter
    public void setAllowTokenAccessWithoutOicSession(boolean allowTokenAccessWithoutOicSession) {
        this.allowTokenAccessWithoutOicSession = allowTokenAccessWithoutOicSession;
    }

    @DataBoundSetter
    public void setAllowedTokenExpirationClockSkewSeconds(Long allowedTokenExpirationClockSkewSeconds) {
        this.allowedTokenExpirationClockSkewSeconds = allowedTokenExpirationClockSkewSeconds;
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

    @Override
    public Filter createFilter(FilterConfig filterConfig) {
        return new ChainedServletFilter(super.createFilter(filterConfig), new Filter() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                    throws IOException, ServletException {

                if (OicSecurityRealm.this.handleTokenExpiration(
                        (HttpServletRequest) request, (HttpServletResponse) response)) {
                    chain.doFilter(request, response);
                }
            }
        });
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
        return new SecurityComponents(new AuthenticationManager() {
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
                        UsernamePasswordAuthenticationToken token =
                                new UsernamePasswordAuthenticationToken(escapeHatchUsername, "", grantedAuthorities);
                        SecurityContextHolder.getContext().setAuthentication(token);
                        OicUserDetails userDetails = new OicUserDetails(escapeHatchUsername, grantedAuthorities);
                        SecurityListener.fireAuthenticated2(userDetails);
                        return token;
                    } else {
                        throw new BadCredentialsException("Wrong username and password: " + authentication);
                    }
                }
                throw new BadCredentialsException("Unexpected authentication type: " + authentication);
            }
        });
    }

    /** Build authorization code flow
     */
    protected AuthorizationCodeFlow buildAuthorizationCodeFlow() {
        AccessMethod tokenAccessMethod = BearerToken.queryParameterAccessMethod();
        HttpExecuteInterceptor authInterceptor =
                new ClientParametersAuthentication(clientId, Secret.toString(clientSecret));
        if (TokenAuthMethod.client_secret_basic.equals(serverConfiguration.getTokenAuthMethod())) {
            tokenAccessMethod = BearerToken.authorizationHeaderAccessMethod();
            authInterceptor = new BasicAuthentication(clientId, Secret.toString(clientSecret));
        }
        AuthorizationCodeFlow.Builder builder = new AuthorizationCodeFlow.Builder(
                        tokenAccessMethod,
                        httpTransport,
                        GsonFactory.getDefaultInstance(),
                        new GenericUrl(serverConfiguration.getTokenServerUrl()),
                        authInterceptor,
                        clientId,
                        serverConfiguration.getAuthorizationServerUrl())
                .setScopes(Arrays.asList(serverConfiguration.getScopes()));

        return builder.build();
    }

    /**
     * Validate post-login redirect URL
     *
     * For security reasons, the login must not redirect outside Jenkins
     * realm. For useablility reason, the logout page should redirect to
     * root url.
     */
    protected String getValidRedirectUrl(String url) {
        final String rootUrl = getRootUrl();
        if (url != null && !url.isEmpty()) {
            try {
                final String redirectUrl = new URL(new URL(rootUrl), url).toString();
                // check redirect url stays within rootUrl
                if (redirectUrl.startsWith(rootUrl)) {
                    // check if redirect is logout page
                    final String logoutUrl = new URL(new URL(rootUrl), OicLogoutAction.POST_LOGOUT_URL).toString();
                    if (redirectUrl.startsWith(logoutUrl)) {
                        return rootUrl;
                    }
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
                    } catch (IllegalArgumentException e) {
                        return HttpResponses.errorWithoutStack(403, Messages.OicSecurityRealm_IdTokenParseError());
                    }
                    if (!validateIdToken(idToken)) {
                        return HttpResponses.errorWithoutStack(401, "Unauthorized");
                    }
                    if (!isNonceDisabled() && !validateNonce(idToken)) {
                        return HttpResponses.errorWithoutStack(401, "Unauthorized");
                    }

                    if (failedCheckOfTokenField(idToken)) {
                        throw new FailedCheckOfTokenException(
                                maybeOpenIdLogoutEndpoint(response.getIdToken(), state, buildOauthCommenceLogin()));
                    }

                    GenericJson userInfo = null;
                    if (!Strings.isNullOrEmpty(getServerConfiguration().getUserInfoServerUrl())) {
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

                    OicCredentials credentials = new OicCredentials(
                            response.getAccessToken(),
                            response.getIdToken(),
                            response.getRefreshToken(),
                            response.getExpiresInSeconds(),
                            CLOCK.millis(),
                            OicSecurityRealm.this.getAllowedTokenExpirationClockSkewSeconds());

                    loginAndSetUserData(username.toString(), idToken, userInfo, credentials);

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
                    serverConfiguration.getJwksServerUrl(),
                    new OicJsonWebTokenVerifier.Builder().setHttpTransportFactory(new HttpTransportFactory() {
                        @Override
                        public HttpTransport create() {
                            return httpTransport;
                        }
                    }));
        }
        return jwtVerifier;
    }

    /** Validate UserInfo signature if available */
    private boolean validateUserInfo(JsonWebSignature userinfo) throws IOException {
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
        HttpRequest request =
                requestFactory.buildGetRequest(new GenericUrl(serverConfiguration.getUserInfoServerUrl()));
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
            String userName, IdToken idToken, GenericJson userInfo, OicCredentials credentials) throws IOException {

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
        String email = determineStringField(emailFieldExpr, idToken, userInfo);
        if (email != null) {
            user.addProperty(new Mailer.UserProperty(email));
        }

        String fullName = determineStringField(fullNameFieldExpr, idToken, userInfo);
        if (fullName != null) {
            user.setFullName(fullName);
        }

        user.addProperty(credentials);

        OicUserDetails userDetails = new OicUserDetails(userName, grantedAuthorities);
        SecurityListener.fireAuthenticated2(userDetails);
        SecurityListener.fireLoggedIn(userName);

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
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = User.get2(authentication);

        Assert.notNull(user, "User must not be null");

        OicCredentials credentials = user.getProperty(OicCredentials.class);

        if (credentials != null) {
            if (this.logoutFromOpenidProvider && !Strings.isNullOrEmpty(serverConfiguration.getEndSessionUrl())) {
                // This ensures that token will be expired at the right time with API Key calls, but no refresh can be
                // made.
                user.addProperty(new OicCredentials(null, null, null, CLOCK.millis()));
            }

            req.setAttribute(ID_TOKEN_REQUEST_ATTRIBUTE, credentials.getIdToken());
        }

        super.doLogout(req, rsp);
    }

    static void ensureStateAttribute(@NonNull HttpSession session, @NonNull String state) {
        session.setAttribute(STATE_REQUEST_ATTRIBUTE, state);
    }

    @Override
    public String getPostLogOutUrl2(StaplerRequest req, Authentication auth) {
        Object idToken = req.getAttribute(ID_TOKEN_REQUEST_ATTRIBUTE);
        Object state = getStateAttribute(req.getSession());
        var openidLogoutEndpoint = maybeOpenIdLogoutEndpoint(
                Objects.toString(idToken, ""), Objects.toString(state), this.postLogoutRedirectUrl);
        if (openidLogoutEndpoint != null) {
            return openidLogoutEndpoint;
        }
        return getFinalLogoutUrl(req, auth);
    }

    @VisibleForTesting
    static Object getStateAttribute(HttpSession session) {
        return session.getAttribute(STATE_REQUEST_ATTRIBUTE);
    }

    @CheckForNull
    private String maybeOpenIdLogoutEndpoint(String idToken, String state, String postLogoutRedirectUrl) {
        final String url = serverConfiguration.getEndSessionUrl();
        if (this.logoutFromOpenidProvider && !Strings.isNullOrEmpty(url)) {
            StringBuilder openidLogoutEndpoint = new StringBuilder(url);

            if (!Strings.isNullOrEmpty(idToken)) {
                openidLogoutEndpoint.append("?id_token_hint=").append(idToken).append("&");
            } else {
                openidLogoutEndpoint.append("?");
            }
            openidLogoutEndpoint.append("state=").append(state);

            if (postLogoutRedirectUrl != null) {
                openidLogoutEndpoint
                        .append("&post_logout_redirect_uri=")
                        .append(URLEncoder.encode(postLogoutRedirectUrl, StandardCharsets.UTF_8));
            }
            return openidLogoutEndpoint.toString();
        }
        return null;
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

    private String ensureRootUrl() {
        String rootUrl = getRootUrl();
        if (rootUrl == null) {
            throw new NullPointerException("Jenkins root url must not be null");
        } else {
            return rootUrl;
        }
    }

    private String buildOauthCommenceLogin() {
        return ensureRootUrl() + getLoginUrl();
    }

    private String buildOAuthRedirectUrl() throws NullPointerException {
        return ensureRootUrl() + "securityRealm/finishLogin";
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

    /**
     * Handles Token Expiration.
     * @throws IOException a low level exception
     */
    public boolean handleTokenExpiration(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
            throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (httpRequest.getRequestURI().endsWith("/logout")) {
            // No need to refresh token when logging out
            return true;
        }

        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return true;
        }

        User user = User.get2(authentication);

        if (isAllowTokenAccessWithoutOicSession()) {
            // check if this is a valid api token based request
            String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Basic ")) {
                String token = new String(Base64.getDecoder().decode(authHeader.substring(6)), StandardCharsets.UTF_8)
                        .split(":")[1];

                if (user.getProperty(ApiTokenProperty.class).matchesPassword(token)) {
                    // this was a valid jenkins token being used, exit this filter and let
                    // the rest of chain be processed
                    return true;
                } // else do nothing and continue evaluating this request
            }
        }

        if (user == null) {
            return true;
        }

        OicCredentials credentials = user.getProperty(OicCredentials.class);

        if (credentials == null) {
            return true;
        }

        if (isExpired(credentials)) {
            if (serverConfiguration.isUseRefreshTokens() && !Strings.isNullOrEmpty(credentials.getRefreshToken())) {
                return refreshExpiredToken(user.getId(), credentials, httpRequest, httpResponse);
            } else if (!isTokenExpirationCheckDisabled()) {
                redirectOrRejectRequest(httpRequest, httpResponse);
                return false;
            }
        }

        return true;
    }

    private void redirectOrRejectRequest(HttpServletRequest req, HttpServletResponse res)
            throws IOException, ServletException {
        if (req.getSession(false) != null || Strings.isNullOrEmpty(req.getHeader("Authorization"))) {
            req.getSession().invalidate();
            res.sendRedirect(Jenkins.get().getSecurityRealm().getLoginUrl());
        } else {
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
        }
    }

    public boolean isExpired(OicCredentials credentials) {
        if (credentials.getExpiresAtMillis() == null) {
            return false;
        }

        return CLOCK.millis() >= credentials.getExpiresAtMillis();
    }

    private boolean refreshExpiredToken(
            String expectedUsername,
            OicCredentials credentials,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse)
            throws IOException {
        AuthorizationCodeFlow flow = buildAuthorizationCodeFlow();

        RefreshTokenRequest request = new RefreshTokenRequest(
                        flow.getTransport(),
                        flow.getJsonFactory(),
                        new GenericUrl(flow.getTokenServerEncodedUrl()),
                        credentials.getRefreshToken())
                .setClientAuthentication(flow.getClientAuthentication())
                .setResponseClass(OicTokenResponse.class);

        try {
            OicTokenResponse tokenResponse = (OicTokenResponse) request.execute();

            LOGGER.log(Level.FINE, "Token refresh request", httpRequest.getRequestURI());

            return handleTokenRefreshResponse(flow, expectedUsername, credentials, tokenResponse, httpResponse);
        } catch (TokenResponseException e) {
            handleTokenRefreshException(e, httpResponse);
            return false;
        }
    }

    private boolean handleTokenRefreshResponse(
            AuthorizationCodeFlow flow,
            String expectedUsername,
            OicCredentials credentials,
            OicTokenResponse tokenResponse,
            HttpServletResponse httpResponse)
            throws IOException {
        String refreshToken = tokenResponse.getRefreshToken();
        String idToken = tokenResponse.getIdToken();

        // Refresh Token Flow is not required to send new ID or Refresh Token, so re-use if not received
        if (idToken == null) {
            idToken = credentials.getIdToken();
            tokenResponse.setIdToken(credentials.getIdToken());
        }

        if (refreshToken == null) {
            refreshToken = credentials.getRefreshToken();
        }

        OicCredentials refreshedCredentials = new OicCredentials(
                tokenResponse.getAccessToken(),
                idToken,
                refreshToken,
                tokenResponse.getExpiresInSeconds(),
                CLOCK.millis(),
                getAllowedTokenExpirationClockSkewSeconds());

        GenericJson userInfo = null;
        IdToken parsedIdToken;

        try {
            parsedIdToken = tokenResponse.parseIdToken();
        } catch (IllegalArgumentException e) {
            httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, Messages.OicSecurityRealm_IdTokenParseError());
            return false;
        }

        if (!validateIdToken(parsedIdToken)) {
            httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
            return false;
        }

        if (failedCheckOfTokenField(parsedIdToken)) {
            httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
            return false;
        }

        if (!Strings.isNullOrEmpty(serverConfiguration.getUserInfoServerUrl())) {
            userInfo = getUserInfo(flow, tokenResponse.getAccessToken());
        }

        String username = determineStringField(userNameFieldExpr, parsedIdToken, userInfo);

        if (!User.idStrategy().equals(expectedUsername, username)) {
            httpResponse.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED, "User name was not the same after refresh request");
            return false;
        }

        loginAndSetUserData(username, parsedIdToken, userInfo, refreshedCredentials);

        return true;
    }

    private void handleTokenRefreshException(TokenResponseException e, HttpServletResponse httpResponse)
            throws IOException {
        TokenErrorResponse details = e.getDetails();

        if ("invalid_grant".equals(details.getError())) {
            // RT expired or session terminated
            if (!isTokenExpirationCheckDisabled()) {
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
            }
        } else {
            LOGGER.warning("Token response error: " + details.getError() + ", error description: "
                    + details.getErrorDescription());
            httpResponse.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Token refresh error, check server logs");
        }
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

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

        @Restricted(NoExternalUse.class) // jelly only
        public Descriptor<OicServerConfiguration> getDefaultServerConfigurationType() {
            return Jenkins.get().getDescriptor(OicServerWellKnownConfiguration.class);
        }
    }
}
