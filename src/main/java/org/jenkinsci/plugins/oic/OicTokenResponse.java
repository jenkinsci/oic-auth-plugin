/*
* The MIT License
*
* Copyright (c) 2022 Michael Doubez
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

import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.util.Key;
import java.util.Objects;

/**  Custom TokenResponse
*
* Customisation includes:
* - expires_in: can be Long or String of Long
*/
public class OicTokenResponse extends TokenResponse {

    /**
     * Lifetime in seconds of the access token (for example 3600 for an hour) or {@code null} for
     * none.
     */
    @Key("expires_in")
    private Object expiresInSeconds;

    /**
     * Returns the lifetime in seconds of the access token (for example 3600 for an hour) or
     * {@code null} for none.
     */
    @Override
    public final Long getExpiresInSeconds() {
    if(expiresInSeconds == null) {
        return null;
    }
    return Long.class.isInstance(expiresInSeconds) ? (Long) expiresInSeconds : Long.valueOf(String.valueOf(expiresInSeconds));
    }

    /**
     * Sets the lifetime in seconds of the access token (for example 3600 for an hour) or {@code null}
     * for none.
     *
     * <p>
     * Overriding is only supported for the purpose of calling the super implementation and changing
     * the return type, but nothing else.
     * </p>
     */
    @Override
    public OicTokenResponse setExpiresInSeconds(Long expiresInSeconds) {
    this.expiresInSeconds = expiresInSeconds;
    return this;
    }

    /** clone */
    @Override
    public OicTokenResponse clone() {
    return (OicTokenResponse) super.clone();
    }

    /**
     * Overriding equals()
     */
    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o == null || !(o instanceof OicTokenResponse)) {
            return false;
        }

        OicTokenResponse oo = (OicTokenResponse) o;

        return super.equals(o) &&
            Objects.equals(getExpiresInSeconds(), oo.getExpiresInSeconds());
    }

    /**
     * Overriding hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
