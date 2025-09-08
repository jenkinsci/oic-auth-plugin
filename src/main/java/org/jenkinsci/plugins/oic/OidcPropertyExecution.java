package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;

public interface OidcPropertyExecution {
    /**
     * Customize the OIDC configuration.
     *
     * @param configuration the OIDC configuration to customize
     */
    default void customizeConfiguration(@NonNull OidcConfiguration configuration) {}

    /**
     * Customize the OIDC client.
     * <br/>
     * Always called after {@link #customizeConfiguration(OidcConfiguration)}.
     *
     * @param client the OIDC client to customize
     */
    default void customizeClient(@NonNull OidcClient client) {}
}
