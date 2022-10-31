/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
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
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.model.Failure;
import hudson.remoting.Base64;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

/**
 * The state of the OpenId connect request.
 *
 * Verifies the validity of the response by comparing the state.
 *
 * @author Kohsuke Kawaguchi - initial author?
 * @author Ryan Campbell - initial author?
 * @author Michael Bischoff - adoptation
 */
@SuppressWarnings("deprecation")
abstract class OicSession {

    private final AuthorizationCodeFlow flow;

    /**
     * An opaque value used by the client to maintain state between the request and callback.
     */
    private final String state = Base64.encode(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)).substring(0,20);
    /**
     * The url the user was trying to navigate to.
     */
    private final String from;
    /**
     * Where it will redirect to once the scopes are approved by the user.
     */
    private final String redirectUrl;
    /**
     * ID Token needed to logout from OpenID Provider
     */
    private String idToken;

    OicSession(AuthorizationCodeFlow flow, String from, String redirectUrl) {
        this.flow = flow;
        this.from = from;
        this.redirectUrl = redirectUrl;
    }

    /**
     * Starts the login session.
     * @return an {@link HttpResponse}
     */
    @SuppressFBWarnings("J2EE_STORE_OF_NON_SERIALIZABLE_OBJECT_INTO_SESSION")
    public HttpResponse doCommenceLogin() {
        // remember this in the session
        Stapler.getCurrentRequest().getSession().setAttribute(SESSION_NAME, this);
        AuthorizationCodeRequestUrl authorizationCodeRequestUrl = flow.newAuthorizationUrl().setState(state).setRedirectUri(redirectUrl);
        return new HttpRedirect(authorizationCodeRequestUrl.toString());
    }

    /**
     * When the identity provider is done with its thing, the user comes back here.
     * @return an {@link HttpResponse}
     */
    public HttpResponse doFinishLogin(StaplerRequest request)  {
        StringBuffer buf = request.getRequestURL();
        if (request.getQueryString() != null) {
            buf.append('?').append(request.getQueryString());
        }
        AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(buf.toString());
        if (!state.equals(responseUrl.getState())) {
            return new Failure("State is invalid");
        }
        String code = responseUrl.getCode();
        if (responseUrl.getError() != null) {
            return new Failure(
                    "Error from provider: " + responseUrl.getError() + ". Details: " + responseUrl.getErrorDescription()
            );
        } else if (code == null) {
            return new Failure("Missing authorization code");
        } else {
            return onSuccess(code);
        }
    }

    /**
     * Where was the user trying to navigate to when they had to login?
     *
     * @return the url the user wants to reach
     */
    protected String getFrom() {
        return from;
    }

    public String getState() {
        return this.state;
    }

    protected abstract HttpResponse onSuccess(String authorizationCode);

    /**
     * Gets the {@link OicSession} associated with HTTP session in the current extend.
     */
    public static OicSession getCurrent() {
        return (OicSession) Stapler.getCurrentRequest().getSession().getAttribute(SESSION_NAME);
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    public String getIdToken()
    {
        return this.idToken;
    }

    private static final String SESSION_NAME = OicSession.class.getName();
}
