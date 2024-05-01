/*
 * The MIT License
 *
 * Copyright (c) 2024 JenkinsCI oic-auth-plugin developers
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

import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.json.webtoken.JsonWebSignature;
import hudson.Util;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * Extend IdTokenVerifier to verify UserInfo webtoken
 */
public class OicJsonWebTokenVerifier extends IdTokenVerifier {

    private static final Logger LOGGER = Logger.getLogger(OicJsonWebTokenVerifier.class.getName());

    /** Bypass Signature verification if JWKS url is not available */
    private boolean jwksServerUrlAvailable;

    /** Payload indicating userInfo */
    private static final IdToken.Payload NO_PAYLOAD = new IdToken.Payload();

    /**
     * Default verifier
     */
    public OicJsonWebTokenVerifier() {
        super();
        jwksServerUrlAvailable = false;
    }

    /**
     * Verifier with custom builder
     */
    public OicJsonWebTokenVerifier(String jwksServerUrl, IdTokenVerifier.Builder builder) {
        super(builder.setCertificatesLocation(jwksServerUrl));
        jwksServerUrlAvailable = (Util.fixEmptyAndTrim(jwksServerUrl) != null);
    }

    /** JWKS verfication enabled - for tests only */
    public boolean isJwksServerUrlAvailable() {
        return jwksServerUrlAvailable;
    }


    /** Verify real idtoken */
    public boolean verifyIdToken(IdToken idToken) throws IOException {
        if (isJwksServerUrlAvailable()) {
            try {
                return verifyOrThrow(idToken);
            } catch(IOException e) {
                LOGGER.warning("IdToken signature verification failed '" + e.toString() + "' - jwks signature verification disabled");
                jwksServerUrlAvailable = false;
            }
        }
        return super.verifyPayload(idToken);
    }

    /** Verify userinfo jwt token */
    public boolean verifyUserInfo(JsonWebSignature userinfo) throws IOException {
        if (isJwksServerUrlAvailable()) {
            try {
                IdToken idToken = new IdToken(
                        userinfo.getHeader(),
                        NO_PAYLOAD, /* bypass verification of payload */
                        userinfo.getSignatureBytes(),
                        userinfo.getSignedContentBytes());
                return verifyOrThrow(idToken);
            } catch(IOException e) {
                LOGGER.warning("UserInfo signature verification failed '" + e.toString() + "' - ignore");
            }
        }
        return true;
    }

    /** hack: verify payload only if idtoken is not userinfo */
    @Override
    protected boolean verifyPayload(IdToken idToken) {
        if (idToken.getPayload() == NO_PAYLOAD) {
            return true;
        }
        return super.verifyPayload(idToken);
    }
}
