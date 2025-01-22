package org.jenkinsci.plugins.oic;

import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;
import org.springframework.lang.NonNull;

public class OicQueryParameterConfiguration extends AbstractDescribableImpl<OicQueryParameterConfiguration>
        implements Serializable {

    private static final long serialVersionUID = 1L;

    private String paramName;
    private String paramValue;

    @DataBoundConstructor
    public OicQueryParameterConfiguration() {}

    public OicQueryParameterConfiguration(@NonNull String paramName, @NonNull String paramValue) {
        if (Util.fixEmptyAndTrim(paramName) == null) {
            throw new IllegalStateException("Parameter name '" + paramName + "' must not be null or empty.");
        }
        setQueryParamName(paramName.trim());
        setQueryParamValue(paramValue.trim());
    }

    @DataBoundSetter
    public void setQueryParamName(String paramName) {
        this.paramName = paramName;
    }

    @DataBoundSetter
    public void setQueryParamValue(String paramValue) {
        this.paramValue = paramValue;
    }

    public String getQueryParamName() {
        return paramName;
    }

    public String getQueryParamValue() {
        return paramValue;
    }

    public String getQueryParamNameEncoded() {
        return paramName != null
                ? URLEncoder.encode(paramName, StandardCharsets.UTF_8).trim()
                : null;
    }

    public String getQueryParamValueEncoded() {
        return paramValue != null
                ? URLEncoder.encode(paramValue, StandardCharsets.UTF_8).trim()
                : null;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<OicQueryParameterConfiguration> {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Query Parameter Configuration";
        }

        @POST
        public FormValidation doCheckQueryParamName(@QueryParameter String queryParamName) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(queryParamName) == null) {
                return FormValidation.error(Messages.OicQueryParameterConfiguration_QueryParameterNameRequired());
            }
            return FormValidation.ok();
        }
    }
}
