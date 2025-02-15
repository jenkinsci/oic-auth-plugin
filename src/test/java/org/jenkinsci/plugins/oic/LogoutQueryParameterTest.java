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
public class LogoutQueryParameterTest {

    @BeforeEach
    public void setUp(JenkinsRule jenkinsRule) {
        jenkinsRule
                .jenkins
                .getDescriptorList(LogoutQueryParameter.class)
                .add(new LogoutQueryParameter.DescriptorImpl());
    }

    @Test
    public void testInvalidKey() throws Exception {
        FormException e = assertThrows(
                Descriptor.FormException.class, () -> new LogoutQueryParameter("id_token_hint", "anything"));
        assertThat(e.getMessage(), is("id_token_hint is a reserved word"));
        assertThat(e.getFormField(), is("key"));
    }

    @Test
    public void testNullKeyOrValue() throws Exception {
        FormException e = assertThrows(Descriptor.FormException.class, () -> new LogoutQueryParameter(null, null));
        assertThat(e.getMessage(), is("key must not be blank"));
        assertThat(e.getFormField(), is("key"));

        new LogoutQueryParameter("test", null);
    }

    @Test
    public void testNoRestrictionsInValue() throws Exception {
        new LogoutQueryParameter("anything", "id_token_hint");
        new LogoutQueryParameter("anything", "");
    }

    @Test
    public void testValidKey() throws Exception {
        LogoutQueryParameter lqp = new LogoutQueryParameter("myKey", "myValue");
        assertThat(lqp.getKey(), is("myKey"));
        assertThat(lqp.getURLEncodedKey(), is("myKey"));
        assertThat(lqp.getValue(), is("myValue"));
        assertThat(lqp.getURLEncodedValue(), is("myValue"));
    }

    @Test
    public void testEmptyValue() throws Exception {
        LogoutQueryParameter lqp = new LogoutQueryParameter("something", "");
        assertThat(lqp.getKey(), is("something"));
        assertThat(lqp.getURLEncodedKey(), is("something"));
        assertThat(lqp.getValue(), is(""));
        assertThat(lqp.getURLEncodedValue(), is(""));
    }

    @Test
    public void testValidKeyWithEscaping() throws Exception {
        LogoutQueryParameter lqp = new LogoutQueryParameter("my Key", "my/Value");
        assertThat(lqp.getKey(), is("my Key"));
        assertThat(lqp.getURLEncodedKey(), is("my+Key"));
        assertThat(lqp.getValue(), is("my/Value"));
        assertThat(lqp.getURLEncodedValue(), is("my%2FValue"));
    }
}
