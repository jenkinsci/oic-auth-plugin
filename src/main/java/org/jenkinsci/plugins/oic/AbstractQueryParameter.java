package org.jenkinsci.plugins.oic;

import hudson.model.Descriptor;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public abstract class AbstractQueryParameter<T extends AbstractQueryParameter<T>>
        extends AbstractKeyValueDescribable<T> {

    public AbstractQueryParameter(String key, String value) throws Descriptor.FormException {
        super(key, value);
    }

    public AbstractQueryParameter(String key, String value, boolean allowEmptyValue) throws Descriptor.FormException {
        super(key, value, allowEmptyValue);
    }

    /**
     * Return {@link #getKey()} encoded with {@code application/x-www-form-urlencoded} in {@code UTF-8}
     */
    public String getURLEncodedKey() {
        return URLEncoder.encode(getKey(), StandardCharsets.UTF_8);
    }

    /**
     * Return {@link #getValue()} encoded with {@code application/x-www-form-urlencoded} in {@code UTF-8}
     */
    public String getURLEncodedValue() {
        return URLEncoder.encode(getValue(), StandardCharsets.UTF_8);
    }
}
