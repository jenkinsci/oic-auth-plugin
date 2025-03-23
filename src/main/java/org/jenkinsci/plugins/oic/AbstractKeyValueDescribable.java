package org.jenkinsci.plugins.oic;

import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.FormValidation.Kind;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.stapler.QueryParameter;

public abstract class AbstractKeyValueDescribable<T extends AbstractKeyValueDescribable<T>>
        extends AbstractDescribableImpl<T> {

    private final String key;
    private final String value;

    /**
     * Create a new instance with the provided key/value combination.
     * @param key non-blank String to use as the key, will be {@code trim}ed before persisting
     * @param value non-blank string for the value, will be {@code trim}ed before persisting
     * @throws Descriptor.FormException if either key/value are {@code null} or are not valid values
     */
    public AbstractKeyValueDescribable(String key, String value) throws Descriptor.FormException {
        this(key, value, false);
    }

    /**
     * Create a new instance with the provided key/value combination.
     * @param key non-blank String to use as the key, will be {@code trim}ed before persisting
     * @param value possibly blank string for the value, will be {@code trim}ed before persisting
     * @param allowBlankValue {@code true} it {@code value} may be blank (but not null)
     * @throws Descriptor.FormException if either key/value are {@code null} or are not valid values
     */
    public AbstractKeyValueDescribable(String key, String value, boolean allowBlankValue)
            throws Descriptor.FormException {
        // formValidation should not error for blank entries so we need to explicitly check them
        if (StringUtils.isBlank(key)) {
            throw new Descriptor.FormException("key must not be blank", "key");
        }
        if (!allowBlankValue && StringUtils.isBlank(value)) {
            throw new Descriptor.FormException("value must not be blank", "value");
        }

        FormValidation keyValidation = getDescriptor().doCheckKey(key);
        if (keyValidation.kind == Kind.ERROR) {
            throw new Descriptor.FormException(keyValidation.getMessage(), "key");
        }
        FormValidation valueValidation = getDescriptor().doCheckValue(value);
        if (valueValidation.kind == Kind.ERROR) {
            throw new Descriptor.FormException(valueValidation.getMessage(), "value");
        }
        this.key = key.trim();
        this.value = value == null ? "" : value.trim();
    }

    public String getKey() {
        return key;
    }

    public String getValue() {
        return value;
    }

    @Override
    public DescriptorImpl<T> getDescriptor() {
        return (DescriptorImpl<T>) super.getDescriptor();
    }

    public static class DescriptorImpl<T extends AbstractKeyValueDescribable<T>> extends Descriptor<T> {

        /**
         * Check the key for validity.
         * In addition to being used by the UI, any FormValidation of {@code Kind.ERROR} will cause a fail to create the describable.
         * By default, this method returns {@link FormValidation#ok()}, subclasses should override this in order to provide any required checking.
         */
        public FormValidation doCheckKey(@SuppressWarnings("unused") @QueryParameter String key) {
            return FormValidation.ok();
        }

        /**
         * Check the key for validity.
         * In addition to being used by the UI, any FormValidation of {@code Kind.ERROR} will cause a fail to create the describable.
         * By default, this method returns {@link FormValidation#ok()}, subclasses should override this in order to provide any required checking.
         */
        public FormValidation doCheckValue(@SuppressWarnings("unused") @QueryParameter String value) {
            return FormValidation.ok();
        }
    }
}
