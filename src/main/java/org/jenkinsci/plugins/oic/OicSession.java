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
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.util.Base64;
import com.google.common.annotations.VisibleForTesting;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.model.Failure;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpSession;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.web.util.UriComponentsBuilder;

import static org.jenkinsci.plugins.oic.OicSecurityRealm.ensureStateAttribute;

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
abstract class OicSession implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * An opaque value used by the client to maintain state between the request and callback.
     */
    @VisibleForTesting
    @NonNull
    String state = Base64.encodeBase64URLSafeString(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8))
            .substring(0, 20);
    /**
     * More random state, this time extending to the id token.
     */
    @VisibleForTesting
    String nonce;
    /**
     * The url the user was trying to navigate to.
     */
    private final String from;
    /**
     * Where it will redirect to once the scopes are approved by the user.
     */
    private final String redirectUrl;
    /**
     * PKCE Verifier code if activated
     */
    String pkceVerifierCode;

    OicSession(String from, String redirectUrl) {
        this.from = from;
        this.redirectUrl = redirectUrl;
        this.withNonceDisabled(false);
    }

    /**
     * Activate or disable Nonce
     */
    public OicSession withNonceDisabled(boolean isDisabled) {
        if (isDisabled) {
            this.nonce = null;
        } else {
            if (this.nonce == null) {
                this.nonce = UUID.randomUUID().toString();
            }
        }
        return this;
    }

    /**
     * Helper class to compute PKCE Challenge
     */
    private static class PKCE {
        /** Challenge code of verifier code */
        public String challengeCode;
        /** Methode used for computing challenge code */
        public String challengeCodeMethod;

        public PKCE(String verifierCode) {
            try {
                byte[] bytes = verifierCode.getBytes(StandardCharsets.UTF_8);
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(bytes, 0, bytes.length);
                byte[] digest = md.digest();
                challengeCode = Base64.encodeBase64URLSafeString(digest);
                challengeCodeMethod = "S256";
            } catch (NoSuchAlgorithmException e) {
                challengeCode = verifierCode;
                challengeCodeMethod = "plain";
            }
        }

        /**
         * Generate base64 verifier code
         */
        public static String generateVerifierCode() {
            try {
                SecureRandom random = SecureRandom.getInstanceStrong();
                byte[] code = new byte[32];
                random.nextBytes(code);
                return Base64.encodeBase64URLSafeString(code);
            } catch (NoSuchAlgorithmException e) {
                return null;
            }
        }
    }

    /**
     * Activate or disable PKCE
     */
    public OicSession withPkceEnabled(boolean isEnabled) {
        if (isEnabled) {
            this.pkceVerifierCode = PKCE.generateVerifierCode();
        } else {
            this.pkceVerifierCode = null;
        }
        return this;
    }

    /**
     * Setup the session - isolate warning suppression
     */
    @SuppressFBWarnings("J2EE_STORE_OF_NON_SERIALIZABLE_OBJECT_INTO_SESSION")
    private void setupOicSession(HttpSession session) {
        // remember this in the session
        session.setAttribute(SESSION_NAME, this);
    }

    /**
     * Starts the login session.
     * @return an {@link HttpResponse}
     */
    public HttpResponse commenceLogin(AuthorizationCodeFlow flow) {
        setupOicSession(Stapler.getCurrentRequest().getSession());
        AuthorizationCodeRequestUrl authorizationCodeRequestUrl =
                flow.newAuthorizationUrl().setState(state).setRedirectUri(redirectUrl);
        if (this.nonce != null) {
            authorizationCodeRequestUrl.set("nonce", this.nonce); // no @Key field defined in AuthorizationRequestUrl
        }

        if (this.pkceVerifierCode != null) {
            PKCE pkce = new PKCE(this.pkceVerifierCode);
            authorizationCodeRequestUrl.setCodeChallengeMethod(pkce.challengeCodeMethod);
            authorizationCodeRequestUrl.setCodeChallenge(pkce.challengeCode);
        }
        return new HttpRedirect(authorizationCodeRequestUrl.toString());
    }

    /**
     * When the identity provider is done with its thing, the user comes back here.
     * @return an {@link HttpResponse}
     */
    public HttpResponse finishLogin(StaplerRequest request, AuthorizationCodeFlow flow) throws IOException {
        StringBuffer buf = request.getRequestURL();
        if (request.getQueryString() != null) {
            buf.append('?').append(request.getQueryString());
        } else {
            // some providers ADFS! post data using a form rather than the queryString.
            Map<String, String[]> parameterMap = request.getParameterMap();
            UriComponentsBuilder queryBuilder = UriComponentsBuilder.fromHttpUrl(buf.toString());
            for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
                queryBuilder.queryParam(entry.getKey(), (Object[]) entry.getValue());
            }
            buf = new StringBuffer(queryBuilder.build().toUriString());
        }
        AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(buf.toString());
        if (!state.equals(responseUrl.getState())) {
            return new Failure("State is invalid");
        }
        if (responseUrl.getError() != null) {
            return new Failure("Error from provider: " + responseUrl.getError() + ". Details: "
                    + responseUrl.getErrorDescription());
        }

        String code = responseUrl.getCode();
        if (code == null) {
            return new Failure("Missing authorization code");
        }

        HttpSession session = request.getSession(false);
        if (session != null) {
            // avoid session fixation
            session.invalidate();
        }
        ensureStateAttribute(request.getSession(true), getState());
        return onSuccess(code, flow);
    }

    /**
     * Where was the user trying to navigate to when they had to login?
     *
     * @return the url the user wants to reach
     */
    protected String getFrom() {
        return from;
    }

    @NonNull
    public String getState() {
        return this.state;
    }

    protected abstract HttpResponse onSuccess(String authorizationCode, AuthorizationCodeFlow flow);

    protected final boolean validateNonce(IdToken idToken) {
        if (idToken == null || this.nonce == null) {
            // validation impossible or disabled
            return true;
        }
        return this.nonce.equals(idToken.getPayload().getNonce());
    }

    /**
     * Gets the {@link OicSession} associated with HTTP session in the current extend.
     */
    public static OicSession getCurrent() {
        return (OicSession) Stapler.getCurrentRequest().getSession().getAttribute(SESSION_NAME);
    }

    private static final String SESSION_NAME = OicSession.class.getName();
}
