package org.jenkinsci.plugins.oic;

import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WithJenkins
public class LoginQueryParameterTest {

    @BeforeEach
    public void setUp(JenkinsRule jenkinsRule) {
        jenkinsRule.jenkins.getDescriptorList(LoginQueryParameter.class).add(new LoginQueryParameter.DescriptorImpl());
    }

    @Test
    public void testInvalidKey() {
        FormException e =
                assertThrows(Descriptor.FormException.class, () -> new LoginQueryParameter("scope", "anything"));
        assertThat(e.getMessage(), is("scope is a reserved word"));
        assertThat(e.getFormField(), is("key"));
    }

    @Test
    public void testNullKeyOrValue() {
        FormException e = assertThrows(Descriptor.FormException.class, () -> new LoginQueryParameter(null, null));
        assertThat(e.getMessage(), is("key must not be blank"));
        assertThat(e.getFormField(), is("key"));

        e = assertThrows(Descriptor.FormException.class, () -> new LoginQueryParameter("test", null));
        assertThat(e.getMessage(), is("value must not be blank"));
        assertThat(e.getFormField(), is("value"));
    }

    @Test
    public void testNoRestrictionsInValue() throws Exception {
        new LoginQueryParameter("anything", "scope");
    }

    @Test
    public void testValidKey() throws Exception {
        LoginQueryParameter lqp = new LoginQueryParameter("myKey", "myValue");
        assertThat(lqp.getKey(), is("myKey"));
        assertThat(lqp.getURLEncodedKey(), is("myKey"));
        assertThat(lqp.getValue(), is("myValue"));
        assertThat(lqp.getURLEncodedValue(), is("myValue"));
    }

    @Test
    public void testValidKeyWithEscaping() throws Exception {
        LoginQueryParameter lqp = new LoginQueryParameter("my Key", "my/Value");
        assertThat(lqp.getKey(), is("my Key"));
        assertThat(lqp.getURLEncodedKey(), is("my+Key"));
        assertThat(lqp.getValue(), is("my/Value"));
        assertThat(lqp.getURLEncodedValue(), is("my%2FValue"));
    }
}
