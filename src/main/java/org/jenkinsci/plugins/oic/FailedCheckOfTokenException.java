package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import java.io.IOException;
import javax.servlet.ServletException;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

/**
 * Exception to be thrown when the received ID Token did not pass the expected check.
 * It offers a link to log out from the OpenID Connect provider.
 */
public class FailedCheckOfTokenException extends RuntimeException implements HttpResponse {
    @CheckForNull
    private final String idpLogoutUrl;

    public FailedCheckOfTokenException(@CheckForNull String idpLogoutUrl) {
        this.idpLogoutUrl = idpLogoutUrl;
    }

    @CheckForNull
    @SuppressWarnings("unused") // stapler/jelly
    public String getIdpLogoutUrl() {
        return idpLogoutUrl;
    }

    @Override
    public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node)
            throws IOException, ServletException {
        req.getView(this, "error").forward(req, rsp);
    }
}
