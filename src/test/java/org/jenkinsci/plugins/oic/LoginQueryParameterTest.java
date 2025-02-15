package org.jenkinsci.plugins.oic;

import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

public class LoginQueryParameterTest {

    @ClassRule
    public static JenkinsRule jr = new JenkinsRule();

    @Test
    public void testInvalidKey() throws Exception {
        FormException e =
                assertThrows(Descriptor.FormException.class, () -> new LoginQueryParameter("scope", "anything"));
        assertThat(e.getMessage(), is("scope is a reserved word"));
        assertThat(e.getFormField(), is("key"));
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
