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

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.jenkinsci.plugins.oic.OicSecurityRealm.PlaceHolder.ABSENT;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
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

import com.fasterxml.jackson.core.JsonParseException;
import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.common.base.Strings;

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
import jenkins.security.SecurityListener;

/**
* Login with OpenID Connect / OAuth 2
*
* @author Michael Bischoff
* @author Steve Arch
*/
@SuppressWarnings("deprecation")
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
    private final String endSessionEndpoint;
    private final String postLogoutRedirectUrl;
    private final boolean escapeHatchEnabled;
    private final String escapeHatchUsername;
    private final Secret escapeHatchSecret;
    private final String escapeHatchGroup;
    private String automanualconfigure;

    /** old field that had an '/' implicitly added at the end, 
     * transient because we no longer want to have this value stored
     * but it's still needed for backwards compatibility */
    private transient String endSessionUrl;
    
    private transient HttpTransport httpTransport;
    private static final Random RANDOM = new Random();

    @DataBoundConstructor
    public OicSecurityRealm(String clientId, String clientSecret, String wellKnownOpenIDConfigurationUrl, String tokenServerUrl, String authorizationServerUrl,
                            String userInfoServerUrl, String userNameField, String tokenFieldToCheckKey, String tokenFieldToCheckValue,
                            String fullNameFieldName, String emailFieldName, String scopes, String groupsFieldName, boolean disableSslVerification,
                            Boolean logoutFromOpenidProvider, String endSessionEndpoint, String postLogoutRedirectUrl, boolean escapeHatchEnabled,
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
           	this.endSessionEndpoint = config.getEndSessionEndpoint();
        } else {
            this.authorizationServerUrl = authorizationServerUrl;
            this.tokenServerUrl = tokenServerUrl;
            this.userInfoServerUrl = userInfoServerUrl;
            this.scopes = Util.fixEmpty(scopes) == null ? "openid email" : scopes;
            this.wellKnownOpenIDConfigurationUrl = null;  // Remove the autoconfig URL
            this.logoutFromOpenidProvider = logoutFromOpenidProvider;
           	this.endSessionEndpoint = endSessionEndpoint;
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
    }

    private Object readResolve() {
        if(httpTransport==null) {
            httpTransport = constructHttpTransport(isDisableSslVerification());
        }
        if(!Strings.isNullOrEmpty(endSessionUrl)) {
        	try {
        		Field field = getClass().getDeclaredField("endSessionEndpoint");
				field.setAccessible(true);
        		field.set(this, endSessionUrl + "/");
			} catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
				LOGGER.log(Level.SEVERE, "Can't set endSessionEndpoint from old value", e);
			}
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

                        if (authentication instanceof UsernamePasswordAuthenticationToken && escapeHatchEnabled) {
                        	randomWait(); // to slowdown brute forcing
                        	if( authentication.getPrincipal().toString().equals(escapeHatchUsername) &&
                        		authentication.getCredentials().toString().equals(escapeHatchSecret.getPlainText())) {
	                                List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
	                                grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
	                                if(isNotBlank(escapeHatchGroup)) {
	                                	grantedAuthorities.add(new SimpleGrantedAuthority(escapeHatchGroup));
	                                }
	                                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
	                                		escapeHatchUsername,
	                                        "",
	                                        grantedAuthorities
	                                );
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
                },
                new UserDetailsService() {
					
					@Override
					public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
						// Retrieve the OicUserProperty to get the list of groups that has to be set in the OicUserDetails object.
						LOGGER.fine("loadUserByUsername in createSecurityComponents called, username: " + username);
						User u = User.get(username, false, Collections.emptyMap());
						if (u == null) {
							LOGGER.fine("loadUserByUsername in createSecurityComponents called, no user '" + username + "' found");
							throw new UsernameNotFoundException(username);
						}
						LOGGER.fine("loadUserByUsername in createSecurityComponents called, user: " + u);
						List<UserProperty> props = u.getAllProperties();
						LOGGER.fine("loadUserByUsername in createSecurityComponents called, number of props: " + props.size());
						List<GrantedAuthority> auths = new ArrayList<>();
						for (UserProperty prop: props) {
							LOGGER.fine("loadUserByUsername in createSecurityComponents called, prop of type: " + prop.getClass().toString());
							if (prop instanceof OicUserProperty) {
								OicUserProperty oicProp = (OicUserProperty) prop;
								LOGGER.fine("loadUserByUsername in createSecurityComponents called, oic prop found with username: " + oicProp.getUserName());
								auths = oicProp.getAuthoritiesAsGrantedAuthorities();
								LOGGER.fine("loadUserByUsername in createSecurityComponents called, oic prop with auths size: " + auths.size());
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
                    AuthorizationCodeTokenRequest tokenRequest = flow.newTokenRequest(authorizationCode)
                        .setRedirectUri(buildOAuthRedirectUrl());
                    // Supplying scope is not allowed when obtaining an access token with an authorization code.
                    tokenRequest.setScopes(Collections.<String>emptyList());

                    IdTokenResponse response = IdTokenResponse.execute(tokenRequest);

                    this.setIdToken(response.getIdToken());

                    IdToken idToken = IdToken.parse(JSON_FACTORY, response.getIdToken());

                    Object username;
                    GenericJson userInfo = null;
                    if (Strings.isNullOrEmpty(userInfoServerUrl)) {
                        username = getField(idToken.getPayload(), userNameField);
                        if(username == null) {
                            return HttpResponses.error(500,"no field '" + userNameField + "' was supplied in the token payload to be used as the username");
                        }
                    } else {
                        userInfo = getUserInfo(flow, response.getAccessToken());
                        username = getField(userInfo, userNameField);
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

        Object value = getField(idToken.getPayload(), tokenFieldToCheckKey);
        if(value == null) {
            return true;
        }

        return !tokenFieldToCheckValue.equals(String.valueOf(value));
    }

    private UsernamePasswordAuthenticationToken loginAndSetUserData(String userName, IdToken idToken, GenericJson userInfo) throws IOException {

        List<GrantedAuthority> grantedAuthorities = determineAuthorities(idToken, userInfo);
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

        User user = User.get2(token);
	if(user == null){
                // should not happen
                throw new IOException("Cannot set OIDC property on anonymous user");
	}
        // Store the list of groups in a OicUserProperty so it can be retrieved later for the UserDetails object.
        user.addProperty(new OicUserProperty(userName, grantedAuthorities));

        if(emailFieldName!=null) {
	        String email = userInfo == null ? getField(idToken, emailFieldName) : (String) getField(userInfo, emailFieldName);
	        if (email != null) {
	            user.addProperty(new Mailer.UserProperty(email));
	        }
        }

        if(fullNameFieldName!=null) {
		    String fullName = userInfo == null ? getField(idToken, fullNameFieldName) : (String) getField(userInfo, fullNameFieldName);
		    if (fullName != null) {
		        user.setFullName(fullName);
		    }
        }

        OicUserDetails userDetails = new OicUserDetails(userName, grantedAuthorities);
        SecurityListener.fireAuthenticated2(userDetails);

        return token;
    }

    private List<GrantedAuthority> determineAuthorities(IdToken idToken, GenericJson userInfo) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);

        if (isNotBlank(groupsFieldName)) {
            if (!Strings.isNullOrEmpty(userInfoServerUrl) && containsField(userInfo, groupsFieldName)) {
                LOGGER.fine("UserInfo contains group field name: " + groupsFieldName + " with value class:" + getField(userInfo, groupsFieldName).getClass());
                @SuppressWarnings("unchecked")
                List<String> groupNames = (List<String>) getField(userInfo, groupsFieldName);
                LOGGER.fine("Number of groups in groupNames: " + groupNames.size());
                for (String groupName : groupNames) {
                    LOGGER.fine("Adding group from UserInfo: " + groupName);
                    grantedAuthorities.add(new SimpleGrantedAuthority(groupName));
                }
            } else if (containsField(idToken.getPayload(), groupsFieldName)) {
                LOGGER.fine("idToken contains group field name: " + groupsFieldName + " with value class:" + getField(idToken.getPayload(), groupsFieldName).getClass());
                @SuppressWarnings("unchecked")
                List<String> groupNames = (List<String>) getField(idToken.getPayload(), groupsFieldName);
                LOGGER.fine("Number of groups in groupNames: " + groupNames.size());
                for (String groupName : groupNames) {
                    LOGGER.fine("Adding group from idToken: " + groupName);
                    grantedAuthorities.add(new SimpleGrantedAuthority(groupName));
                }
            } else {
                LOGGER.warning("idToken and userInfo did not contain group field name: " + groupsFieldName);
            }
        } else {
            LOGGER.fine("Not adding groups because groupsFieldName is not set. groupsFieldName=" + groupsFieldName);
        }

        return grantedAuthorities;
    }

    private String getField(IdToken idToken, String fullNameFieldName) {
        Object value = getField(idToken.getPayload(), fullNameFieldName);
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
    public String getPostLogOutUrl2(StaplerRequest req, Authentication auth) {
        if (this.logoutFromOpenidProvider && !Strings.isNullOrEmpty(this.endSessionEndpoint)) {
            StringBuilder openidLogoutEndpoint = new StringBuilder(this.endSessionEndpoint);
            openidLogoutEndpoint.append("?id_token_hint=").append(req.getAttribute(ID_TOKEN_REQUEST_ATTRIBUTE));
            openidLogoutEndpoint.append("&state=").append(req.getAttribute(STATE_REQUEST_ATTRIBUTE));

            if (this.postLogoutRedirectUrl != null) {
                openidLogoutEndpoint.append("&post_logout_redirect_uri=").append(this.postLogoutRedirectUrl);
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

    private String determineRedirectTarget(@QueryParameter String from, @Header("Referer") String referer) {
        String target;
        if (from != null) {
            target = from;
        } else if (referer != null) {
            target = referer;
        } else {
            target = Jenkins.get().getRootUrlFromRequest();
        }
        return target;
    }

    private String buildOAuthRedirectUrl() throws NullPointerException {
        String rootUrl = Jenkins.get().getRootUrlFromRequest();
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
    	OicSession currentSession = OicSession.getCurrent();
    	if(currentSession==null) {
    		LOGGER.fine("No session to resume (perhaps jenkins was restarted?)");
    		return HttpResponses.errorWithoutStack(401, "Unauthorized");
    	}
        return currentSession.doFinishLogin(request);
    }

    /**
     * Looks up the value of a field by it's key based on some json.
     * keys with dot notation allow to denote nested structures.
     *
     * Keys containing dot's take precedence over nested values, by using "
     * one can denote (partly) nested structures. dot notation feels more natural but
     * '"' is the only illegal character in json strings
     *
     * given:
     * {@code
     * {
     *     "do": {
     *         "re.mi": "a"
     *     },
     *     "do": {
     *         "re": {
     *             "mi": "b"
     *         }
     *     },
     *     "do.re": {
     *         "mi": "c"
     *     }
     *     "do.re.mi": "d",
     * }
     * }
     * {@literal
     *  'do.re.mi' -&gt; 'd'
     *  'do"re.mi' -> 'a'
     *  'do"re"mi' -> 'b'
     *  'do.re"mi' -> 'c'
     * }
     *
     * @param payload   json payload to search
     * @param field     field key
     * @return value or null
     */
    public Object getField(GenericJson payload, String field) {
        Object value = lookup(payload, field);
        if(value == ABSENT) {
            return null;
        }
        return value;
    }

    /**
     * @see #getField(GenericJson, String)
     * @param payload parsed json
     * @param field to lookup a value
     * @return true if there is a value associated with the field
     */
    public boolean containsField(GenericJson payload, String field) {
        return lookup(payload, field) != ABSENT;
    }

    enum PlaceHolder {
        ABSENT
    }

    @SuppressWarnings("rawtypes")
	private Object lookup(Map parsedJson, String key) {
        if(key.contains("\"")) {
            int indexMarker = key.indexOf('\"');
            Object nested = parsedJson.get(key.substring(0,indexMarker));
            if(nested == null || !(nested instanceof Map)) {
                return parsedJson.containsKey(key.substring(0,indexMarker)) ? null : ABSENT;
            }
            return lookup((Map) nested, key.substring(indexMarker));
        }

        String firstPart = key;
        int lastPos = key.length();
        do {
            firstPart = firstPart.substring(0, lastPos);
            Object value = parsedJson.get(firstPart);
            if (value != null) {
                if(firstPart.length() == key.length()) {
                    if(value instanceof Map) {
                        return ABSENT;
                    }
                    return value;
                }
                if(value instanceof Map) {
                    Object nested = lookup((Map) value, key.substring(firstPart.length()+1,key.length()));
                    if(nested != null) {
                        return nested;
                    }
                }
            }
            lastPos = firstPart.lastIndexOf('.');
        } while (lastPos!=-1);
        return parsedJson.containsKey(firstPart) ? null : ABSENT;
    }


    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        public boolean isAuto() {
            SecurityRealm realm = Jenkins.get().getSecurityRealm();
            return realm instanceof OicSecurityRealm &&
                   StringUtils.isNotBlank(((OicSecurityRealm)realm).getWellKnownOpenIDConfigurationUrl());
        }

        public boolean isManual() {
            return Jenkins.get().getSecurityRealm() instanceof OicSecurityRealm && !isAuto();
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

        public FormValidation doCheckEndSessionEndpoint(@QueryParameter String endSessionEndpoint) {
            if (endSessionEndpoint == null || endSessionEndpoint.equals("")) {
                return FormValidation.error("End Session URL Key is required.");
            }
            try {
                new URL(endSessionEndpoint);
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
