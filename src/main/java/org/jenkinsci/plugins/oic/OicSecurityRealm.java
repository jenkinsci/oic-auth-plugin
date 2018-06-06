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

import com.fasterxml.jackson.core.JsonParseException;
import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.common.base.Strings;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.util.HttpResponses;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.HttpResponse;
import org.springframework.dao.DataAccessException;

import javax.servlet.ServletException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
* Login with OpenID Connect / OAuth 2
*
* @author Michael Bischoff
* @author Steve Arch
*/
public class OicSecurityRealm extends SecurityRealm {
	private static final Logger LOGGER = Logger.getLogger(OicSecurityRealm.class.getName());
	
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();
    private static final String ID_TOKEN_REQUEST_ATTRIBUTE = "oic-id-token";
    private static final String STATE_REQUEST_ATTRIBUTE = "oic-state";

    private final String clientId;
    private final Secret clientSecret;
    private final String wellKnownOpenIDConfigurationUrl;
    private final String tokenServerUrl;
    private final String authorizationServerUrl;
    private final String userInfoServerUrl;
    private final String userNameField;
    private final String tokenFieldToCheckKey;
    private final String tokenFieldToCheckValue;
    private final String fullNameFieldName;
    private final String emailFieldName;
    private final String groupsFieldName;
    private final String scopes;
    private final boolean disableSslVerification;
    private final boolean logoutFromOpenidProvider;
    private final String endSessionUrl;
    private final String postLogoutRedirectUrl;
    private final boolean escapeHatchEnabled;
    private final String escapeHatchUsername;
    private final Secret escapeHatchSecret;
    private final String escapeHatchGroup;

    private transient HttpTransport httpTransport;
    private transient Random random;

    @DataBoundConstructor
    public OicSecurityRealm(String clientId, String clientSecret, String wellKnownOpenIDConfigurationUrl, String tokenServerUrl, String authorizationServerUrl,
                            String userInfoServerUrl, String userNameField, String tokenFieldToCheckKey, String tokenFieldToCheckValue,
                            String fullNameFieldName, String emailFieldName, String scopes, String groupsFieldName, boolean disableSslVerification,
                            Boolean logoutFromOpenidProvider, String endSessionUrl, String postLogoutRedirectUrl, boolean escapeHatchEnabled,
                            String escapeHatchUsername, String escapeHatchSecret, String escapeHatchGroup, String automanualconfigure) throws IOException {
        this.httpTransport = constructHttpTransport(disableSslVerification);

        this.clientId = clientId;
        this.clientSecret = Secret.fromString(clientSecret);
        if("auto".equals(automanualconfigure)) {
            // Get the well-known configuration from the specified URL
            this.wellKnownOpenIDConfigurationUrl = Util.fixEmpty(wellKnownOpenIDConfigurationUrl);
            URL url = new URL(wellKnownOpenIDConfigurationUrl);
            HttpRequest request = httpTransport.createRequestFactory().buildGetRequest(new GenericUrl(url));
            com.google.api.client.http.HttpResponse response = request.execute();

            WellKnownOpenIDConfigurationResponse config = OicSecurityRealm.JSON_FACTORY
                    .fromInputStream(response.getContent(), Charset.defaultCharset(),
                            WellKnownOpenIDConfigurationResponse.class);

            this.authorizationServerUrl = config.getAuthorizationEndpoint();
            this.tokenServerUrl = config.getTokenEndpoint();
            this.userInfoServerUrl = config.getUserinfoEndpoint();
            this.scopes = config.getScopesSupported() != null && !config.getScopesSupported().isEmpty() ? StringUtils.join(config.getScopesSupported(), " ") : "openid email";
            this.logoutFromOpenidProvider = logoutFromOpenidProvider != null;
            this.endSessionUrl = config.getEndSessionEndpoint();
        } else {
            this.authorizationServerUrl = authorizationServerUrl;
            this.tokenServerUrl = tokenServerUrl;
            this.userInfoServerUrl = userInfoServerUrl;
            this.scopes = Util.fixEmpty(scopes) == null ? "openid email" : scopes;
            this.wellKnownOpenIDConfigurationUrl = null;  // Remove the autoconfig URL
            this.logoutFromOpenidProvider = logoutFromOpenidProvider;
            this.endSessionUrl = endSessionUrl;
        }

        this.userNameField = Util.fixEmpty(userNameField) == null ? "sub" : userNameField;
        this.tokenFieldToCheckKey = Util.fixEmpty(tokenFieldToCheckKey);
        this.tokenFieldToCheckValue = Util.fixEmpty(tokenFieldToCheckValue);
        this.fullNameFieldName = Util.fixEmpty(fullNameFieldName);
        this.emailFieldName = Util.fixEmpty(emailFieldName);
        this.groupsFieldName = Util.fixEmpty(groupsFieldName);
        this.disableSslVerification = disableSslVerification;
        this.postLogoutRedirectUrl = postLogoutRedirectUrl;
        this.escapeHatchEnabled = escapeHatchEnabled;
        this.escapeHatchUsername = Util.fixEmpty(escapeHatchUsername);
        this.escapeHatchSecret = Secret.fromString(escapeHatchSecret);
        this.escapeHatchGroup = Util.fixEmpty(escapeHatchGroup);

        this.random = new Random();
    }

    private Object readResolve() {
        if(httpTransport==null) {
            httpTransport = constructHttpTransport(isDisableSslVerification());
        }
        if(random==null) {
            random = new Random();
        }
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
        return clientSecret;
    }

    public String getWellKnownOpenIDConfigurationUrl() {
        return wellKnownOpenIDConfigurationUrl;
    }

    public String getTokenServerUrl() {
        return tokenServerUrl;
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
        return scopes;
    }

    public boolean isDisableSslVerification() {
        return disableSslVerification;
    }

    public boolean isLogoutFromOpenidProvider() {
        return logoutFromOpenidProvider;
    }

    public String getEndSessionUrl() {
        return endSessionUrl;
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

    @Override
    public String getLoginUrl() {
        //Login begins with our doCommenceLogin(String,String) method
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
                        if (authentication instanceof AnonymousAuthenticationToken)
                            return authentication;
                        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                    }
                },
                new UserDetailsService() {
					
					@Override
					public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
						// Retrieve the OicUserProperty to get the list of groups that has to be set in the OicUserDetails object.
						LOGGER.fine("loadUserByUsername in createSecurityComponents called, username: " + username);
						User u = User.get(username);
						LOGGER.fine("loadUserByUsername in createSecurityComponents called, user: " + u);
						List<UserProperty> props = u.getAllProperties();
						LOGGER.fine("loadUserByUsername in createSecurityComponents called, number of props: " + props.size());
						GrantedAuthority[] auths = new GrantedAuthority[0];
						for (UserProperty prop: props) {
							LOGGER.fine("loadUserByUsername in createSecurityComponents called, prop of type: " + prop.getClass().toString());
							if (prop instanceof OicUserProperty) {
								OicUserProperty oicProp = (OicUserProperty) prop;
								LOGGER.fine("loadUserByUsername in createSecurityComponents called, oic prop found with username: " + oicProp.getUserName());
								auths = oicProp.getAuthoritiesAsGrantedAuthorities();
								LOGGER.fine("loadUserByUsername in createSecurityComponents called, oic prop with auths size: " + auths.length);
							}
						}
						return new OicUserDetails(username, auths);
					}
				}
        );
    }

    /**
     * Handles the the securityRealm/commenceLogin resource and sends the user off to the IdP
     * @param from the relative URL to the page that the user has just come from
     * @param referer the HTTP referer header (where to redirect the user back to after login has finished)
     * @return an {@link HttpResponse} object
    */
    public HttpResponse doCommenceLogin(@QueryParameter String from, @Header("Referer") final String referer) {
        final String redirectOnFinish = determineRedirectTarget(from, referer);

        final AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(
                BearerToken.queryParameterAccessMethod(),
                httpTransport,
                JSON_FACTORY,
                new GenericUrl(tokenServerUrl),
                new ClientParametersAuthentication(
                        clientId,
                        clientSecret.getPlainText()
                ),
                clientId,
                authorizationServerUrl
        )
            .setScopes(Arrays.asList(scopes))
            .build();

        return new OicSession(flow, from, buildOAuthRedirectUrl()) {
            @Override
            public HttpResponse onSuccess(String authorizationCode) {
                try {
                    IdTokenResponse response = IdTokenResponse.execute(
                            flow.newTokenRequest(authorizationCode).setRedirectUri(buildOAuthRedirectUrl()));

                    this.setIdToken(response.getIdToken());

                    IdToken idToken = IdToken.parse(JSON_FACTORY, response.getIdToken());

                    Object username;
                    GenericJson userInfo = null;
                    if (Strings.isNullOrEmpty(userInfoServerUrl)) {
                        username = idToken.getPayload().get(userNameField);
                        if(username == null) {
                            return HttpResponses.error(500,"no field '" + userNameField + "' was supplied in the token payload to be used as the username");
                        }
                    } else {
                        userInfo = getUserInfo(flow, response.getAccessToken());
                        username = userInfo.get(userNameField);
                        if(username == null) {
                            return HttpResponses.error(500,"no field '" + userNameField + "' was supplied by the UserInfo payload to be used as the username");
                        }
                    }

                    if(failedCheckOfTokenField(idToken)) {
                        return HttpResponses.errorWithoutStack(401, "Unauthorized");
                    }

                    flow.createAndStoreCredential(response, null);

                    loginAndSetUserData(username.toString(), idToken, userInfo);

                    return new HttpRedirect(redirectOnFinish);

                } catch (IOException e) {
                    return HttpResponses.error(500,e);
                }

            }
        }.doCommenceLogin();
    }

    public HttpResponse doEscapeHatch(@QueryParameter("j_username") String username, @QueryParameter("j_password") String password) {
        randomWait(); // to slowdown brute forcing
        if(!isEscapeHatchEnabled()) {
            return HttpResponses.redirectViaContextPath("loginError");
        }
        if(this.escapeHatchUsername == null || this.escapeHatchSecret == null) {
            return HttpResponses.redirectViaContextPath("loginError");
        }
        if(escapeHatchUsername.equalsIgnoreCase(username) && escapeHatchSecret.getPlainText().equals(password)) {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
            if(isNotBlank(escapeHatchGroup)) {
                authorities.add(new GrantedAuthorityImpl(escapeHatchGroup));
            }
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    "escape-hatch-admin",
                    "",
                    authorities.toArray(new GrantedAuthority[authorities.size()])
            );
            SecurityContextHolder.getContext().setAuthentication(token);
            return HttpRedirect.CONTEXT_ROOT;
        }
        return HttpResponses.redirectViaContextPath("loginError");
    }

    private void randomWait() {
        try {
            Thread.sleep(1000 + random.nextInt(1000));
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
        request.setParser(new JsonObjectParser(flow.getJsonFactory()));
        request.setThrowExceptionOnExecuteError(false);
        com.google.api.client.http.HttpResponse response = request.execute();
        if (response.isSuccessStatusCode()) {
            return response.parseAs(GenericJson.class);
        }
        throw new HttpResponseException(response);
    }

    private boolean failedCheckOfTokenField(IdToken idToken) {
        if(tokenFieldToCheckKey == null || tokenFieldToCheckValue == null) {
            return false;
        }

        Object value = idToken.getPayload().get(tokenFieldToCheckKey);
        if(value == null) {
            return true;
        }

        return tokenFieldToCheckValue.equals(String.valueOf(value));
    }

    private UsernamePasswordAuthenticationToken loginAndSetUserData(String userName, IdToken idToken, GenericJson userInfo) throws IOException {

        GrantedAuthority[] grantedAuthorities = determineAuthorities(idToken, userInfo);
        if(LOGGER.isLoggable(Level.FINEST)) {
		    StringBuilder grantedAuthoritiesAsString = new StringBuilder("(");
		    for(GrantedAuthority grantedAuthority : grantedAuthorities) {
		        grantedAuthoritiesAsString.append(" ").append(grantedAuthority.getAuthority());
            }
            grantedAuthoritiesAsString.append(" )");
		    LOGGER.finest("GrantedAuthorities:" + grantedAuthoritiesAsString);
        }

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userName, "", grantedAuthorities);

        SecurityContextHolder.getContext().setAuthentication(token);

        User user = User.get(token.getName());
        // Store the list of groups in a OicUserProperty so it can be retrieved later for the UserDetails object.
        user.addProperty(new OicUserProperty(userName, grantedAuthorities));

        String email = userInfo == null ? getField(idToken, emailFieldName) : (String) userInfo.get(emailFieldName);
        if (email != null) {
            user.addProperty(new Mailer.UserProperty(email));
        }

        String fullName = userInfo == null ? getField(idToken, fullNameFieldName) : (String) userInfo.get(fullNameFieldName);
        if (fullName != null) {
            user.setFullName(fullName);
        }

        return token;
    }

    private GrantedAuthority[] determineAuthorities(IdToken idToken, GenericJson userInfo) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();
        grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);

        if (isNotBlank(groupsFieldName)) {
            if(Strings.isNullOrEmpty(userInfoServerUrl)) {
                if (idToken.getPayload().containsKey(groupsFieldName)) {
                    LOGGER.fine("idToken contains group field name: " + groupsFieldName + " with value class:" + idToken.getPayload().get(groupsFieldName).getClass());
                    @SuppressWarnings("unchecked")
                    List<String> groupNames = (List<String>) idToken.getPayload().get(groupsFieldName);
                    LOGGER.fine("Number of groups in groupNames: " + groupNames.size());
                    for (String groupName : groupNames) {
                        LOGGER.fine("Adding group from idToken: " + groupName);
                        grantedAuthorities.add(new GrantedAuthorityImpl(groupName));
                    }
                } else {
                    LOGGER.warning("idToken did not contain group field name: " + groupsFieldName);
                }
            } else {
                if (userInfo.containsKey(groupsFieldName)) {
                    LOGGER.fine("UserInfo contains group field name: " + groupsFieldName + " with value class:" + userInfo.get(groupsFieldName).getClass());
                    @SuppressWarnings("unchecked")
                    List<String> groupNames = (List<String>) userInfo.get(groupsFieldName);
                    LOGGER.fine("Number of groups in groupNames: " + groupNames.size());
                    for (String groupName : groupNames) {
                        LOGGER.fine("Adding group from UserInfo: " + groupName);
                        grantedAuthorities.add(new GrantedAuthorityImpl(groupName));
                    }
                } else {
                    LOGGER.warning("UserInfo did not contain group field name: " + groupsFieldName);
                }
            }
        } else {
            LOGGER.fine("Not adding groups because groupsFieldName is not set. groupsFieldName=" + groupsFieldName);
        }

        return grantedAuthorities.toArray(new GrantedAuthority[grantedAuthorities.size()]);
    }

    private String getField(IdToken idToken, String fullNameFieldName) {
        Object value = idToken.getPayload().get(fullNameFieldName);
        if(value != null) {
            return String.valueOf(value);
        }
        return null;
    }

    public void doLogout(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        OicSession oicSession = OicSession.getCurrent();
        if(oicSession!=null) {
            // session will be invalidated but we still need this data for our redirect.
            req.setAttribute(ID_TOKEN_REQUEST_ATTRIBUTE, oicSession.getIdToken());
            req.setAttribute(STATE_REQUEST_ATTRIBUTE, oicSession.getState());
        }
        super.doLogout(req, rsp);
    }

    @Override
    public String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        if (this.logoutFromOpenidProvider) {
            StringBuilder openidLogoutEndpoint = new StringBuilder(this.endSessionUrl);
            openidLogoutEndpoint.append("/?id_token_hint=").append(req.getAttribute(ID_TOKEN_REQUEST_ATTRIBUTE));
            openidLogoutEndpoint.append("&state=").append(req.getAttribute(STATE_REQUEST_ATTRIBUTE));

            if (this.postLogoutRedirectUrl != null) {
                openidLogoutEndpoint.append("&post_logout_redirect_uri=").append(this.postLogoutRedirectUrl);
            }
            return openidLogoutEndpoint.toString();
        }

        return getFinalLogoutUrl(req, auth);
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    private String getFinalLogoutUrl(StaplerRequest req, Authentication auth) {
        // if we just redirect to the root and anonymous does not have Overall read then we will start a login all over again.
        // we are actually anonymous here as the security context has been cleared
        if (Jenkins.getInstance().hasPermission(Jenkins.READ)) {
            return super.getPostLogOutUrl(req, auth);
        }
        return req.getContextPath() + "/" + OicLogoutAction.POST_LOGOUT_URL;
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    private String determineRedirectTarget(@QueryParameter String from, @Header("Referer") String referer) {
        String target;
        if (from != null) {
            target = from;
        } else if (referer != null) {
            target = referer;
        } else {
            target = Jenkins.getInstance().getRootUrl();
        }
        return target;
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    private String buildOAuthRedirectUrl() throws NullPointerException {
        String rootUrl = Jenkins.getInstance().getRootUrl();
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
    public HttpResponse doFinishLogin(StaplerRequest request) {
        return OicSession.getCurrent().doFinishLogin(request);
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
        public boolean isAuto() {
            SecurityRealm realm = Jenkins.getInstance().getSecurityRealm();
            return realm instanceof OicSecurityRealm &&
                   StringUtils.isNotBlank(((OicSecurityRealm)realm).getWellKnownOpenIDConfigurationUrl());
        }

        @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
        public boolean isManual() {
            return Jenkins.getInstance().getSecurityRealm() instanceof OicSecurityRealm && !isAuto();
        }

        public String getDisplayName() {
            return "Login with Openid Connect";
        }

        public FormValidation doCheckClientId(@QueryParameter String clientId) {
            if (clientId == null || clientId.trim().length() == 0) {
                return FormValidation.error("Client id is required.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckClientSecret(@QueryParameter String clientSecret) {
            if (clientSecret == null || clientSecret.trim().length() == 0) {
                return FormValidation.error("Client secret is required.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckWellKnownOpenIDConfigurationUrl(@QueryParameter String wellKnownOpenIDConfigurationUrl, @QueryParameter boolean disableSslVerification) {
            try {
                URL url = new URL(wellKnownOpenIDConfigurationUrl);
                HttpRequest request = constructHttpTransport(disableSslVerification).createRequestFactory()
                                                                    .buildGetRequest(new GenericUrl(url));
                com.google.api.client.http.HttpResponse response = request.execute();

                // Try to parse the response. If it's not valid, a JsonParseException will be thrown indicating
                // that it's not a valid JSON describing an OpenID Connect endpoint
                WellKnownOpenIDConfigurationResponse config = OicSecurityRealm.JSON_FACTORY
                        .fromInputStream(response.getContent(), Charset.defaultCharset(),
                                WellKnownOpenIDConfigurationResponse.class);
                if(config.getAuthorizationEndpoint() == null || config.getTokenEndpoint() == null) {
                    return FormValidation.warning("URL does seem to describe OpenID Connect endpoints");
                }

                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, "Not a valid url.");
            } catch (HttpResponseException e) {
                return FormValidation.error(e, "Could not retrieve well-known config %d %s",
                        e.getStatusCode(), e.getStatusMessage());
            } catch (JsonParseException e) {
                return FormValidation.error(e, "Could not parse response");
            } catch (IOException e) {
                return FormValidation.error(e, "Error when retrieving well-known config");
            }
        }

        public FormValidation doCheckTokenServerUrl(@QueryParameter String tokenServerUrl) {
            if (tokenServerUrl == null) {
                return FormValidation.error("Token Server Url Key is required.");
            }
            try {
                new URL(tokenServerUrl);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e,"Not a valid url.");
            }
        }

        public FormValidation doCheckAuthorizationServerUrl(@QueryParameter String authorizationServerUrl) {
            if (authorizationServerUrl == null) {
                return FormValidation.error("Token Server Url Key is required.");
            }
            try {
                new URL(authorizationServerUrl);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e,"Not a valid url.");
            }
        }

        public FormValidation doCheckUserNameField(@QueryParameter String userNameField) {
            if (userNameField == null || userNameField.trim().length() == 0) {
                return FormValidation.ok("Using 'sub'.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckScopes(@QueryParameter String scopes) {
            if (scopes == null || scopes.trim().length() == 0) {
                return FormValidation.ok("Using 'openid email'.");
            }
            if(!scopes.toLowerCase().contains("openid")) {
                return FormValidation.warning("Are you sure you don't want to include 'openid' as an scope?");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckEndSessionUrl(@QueryParameter String endSessionUrl) {
            if (endSessionUrl == null || endSessionUrl.equals("")) {
                return FormValidation.error("End Session URL Key is required.");
            }
            try {
                new URL(endSessionUrl);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e,"Not a valid url.");
            }
        }

        public FormValidation doCheckPostLogoutRedirectUrl(@QueryParameter String postLogoutRedirectUrl) {
            if (postLogoutRedirectUrl != null && !postLogoutRedirectUrl.equals("")) {
                try {
                    new URL(postLogoutRedirectUrl);
                    return FormValidation.ok();
                } catch (MalformedURLException e) {
                    return FormValidation.error(e,"Not a valid url.");
                }
            }

            return FormValidation.ok();
        }
    }
}
