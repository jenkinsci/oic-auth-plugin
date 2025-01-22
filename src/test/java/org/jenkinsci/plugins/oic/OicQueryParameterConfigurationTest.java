package org.jenkinsci.plugins.oic;

import hudson.Util;
import hudson.util.FormValidation;
import org.hamcrest.Matcher;
import org.jenkinsci.plugins.oic.OicQueryParameterConfiguration.DescriptorImpl;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.jvnet.hudson.test.JenkinsMatchers.hasKind;

public class OicQueryParameterConfigurationTest {

    @ClassRule
    public static JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    @WithoutJenkins
    public void testOicQueryParameterConfiguration() {
        assertThrows(IllegalStateException.class, () -> new OicQueryParameterConfiguration("", ""));
    }

    @Test
    @WithoutJenkins
    public void testQueryParameterDecoded() {
        OicQueryParameterConfiguration configClean = new OicQueryParameterConfiguration("key-1", "value-1");
        assertEquals("key-1", configClean.getQueryParamName());
        assertEquals("key-1", configClean.getQueryParamNameEncoded());
        assertEquals("value-1", configClean.getQueryParamValue());
        assertEquals("value-1", configClean.getQueryParamValueEncoded());

        OicQueryParameterConfiguration configEmptyValue = new OicQueryParameterConfiguration("key-2", "");
        assertEquals("key-2", configEmptyValue.getQueryParamName());
        assertEquals("key-2", configEmptyValue.getQueryParamNameEncoded());
        assertEquals("", configEmptyValue.getQueryParamValue());
        assertEquals("", configEmptyValue.getQueryParamValueEncoded());
        configEmptyValue.setQueryParamName(null);
        assertNull(configEmptyValue.getQueryParamName());
        assertNull(configEmptyValue.getQueryParamNameEncoded());
        configEmptyValue.setQueryParamValue(null);
        assertNull(configEmptyValue.getQueryParamValue());
        assertNull(configEmptyValue.getQueryParamValueEncoded());

        OicQueryParameterConfiguration config =
                new OicQueryParameterConfiguration("key-a\"b/c?d#e:f@g&h=i+j$+k,l", "value-a\"b/c?d#e:f@g&h=i+j$+k,l");
        assertEquals("key-a\"b/c?d#e:f@g&h=i+j$+k,l", config.getQueryParamName());
        assertEquals("key-a%22b%2Fc%3Fd%23e%3Af%40g%26h%3Di%2Bj%24%2Bk%2Cl", config.getQueryParamNameEncoded());
        assertEquals("value-a\"b/c?d#e:f@g&h=i+j$+k,l", config.getQueryParamValue());
        assertEquals("value-a%22b%2Fc%3Fd%23e%3Af%40g%26h%3Di%2Bj%24%2Bk%2Cl", config.getQueryParamValueEncoded());
    }

    @Test
    public void testDoCheckQueryParamName() {
        DescriptorImpl descriptor = getDescriptor();
        assertThat(
                descriptor.doCheckQueryParamName(null),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Query parameter name is required.")));
        assertThat(
                descriptor.doCheckQueryParamName(""),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Query parameter name is required.")));
        assertThat(descriptor.doCheckQueryParamName("test"), hasKind(FormValidation.Kind.OK));
    }

    private static DescriptorImpl getDescriptor() {
        return (DescriptorImpl) jenkinsRule.jenkins.getDescriptor(OicQueryParameterConfiguration.class);
    }

    private static Matcher<FormValidation> withMessage(String message) {
        // the FormValidation message will be escaped for HTML, so we escape what we expect.
        return hasProperty("message", is(Util.escape(message)));
    }
}
