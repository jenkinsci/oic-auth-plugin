package org.jenkinsci.plugins.oic.properties;

import static org.apache.commons.lang.StringUtils.isNotBlank;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.security.SecurityRealm;
import hudson.security.csrf.CrumbExclusion;
import hudson.util.Secret;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.regex.Pattern;
import jenkins.security.FIPS140;
import jenkins.security.SecurityListener;
import org.jenkinsci.plugins.oic.OicProperty;
import org.jenkinsci.plugins.oic.OicPropertyDescriptor;
import org.jenkinsci.plugins.oic.OicUserDetails;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCrypt;

/**
 * Escape hatch for authentication, allowing users to log in with a username and password.
 * This is intended for emergency access and should be used with caution.
 */
public class EscapeHatch extends OicProperty {
    public static final Pattern B_CRYPT_PATTERN = Pattern.compile("\\A\\$[^$]+\\$\\d+\\$[./0-9A-Za-z]{53}");

    @CheckForNull
    private final String username;

    @CheckForNull
    private final String group;

    @NonNull
    private final Secret secret;

    @DataBoundConstructor
    public EscapeHatch(@NonNull String username, @CheckForNull String group, @NonNull Secret secret) {
        if (FIPS140.useCompliantAlgorithms()) {
            throw new IllegalStateException("Cannot use Escape Hatch in FIPS-140 mode");
        }
        this.username = Util.fixEmptyAndTrim(username);
        this.group = Util.fixEmptyAndTrim(group);
        // ensure secret is BCrypt hash
        String secretAsString = Secret.toString(secret);
        if (B_CRYPT_PATTERN.matcher(secretAsString).matches()) {
            this.secret = secret;
        } else {
            this.secret = Secret.fromString(BCrypt.hashpw(secretAsString, BCrypt.gensalt()));
        }
    }

    @CheckForNull
    public String getUsername() {
        return username;
    }

    @CheckForNull
    public String getGroup() {
        return group;
    }

    @NonNull
    public Secret getSecret() {
        return secret;
    }

    /**
     * Random generator needed for robust random wait
     */
    private static final Random RANDOM = new Random();

    private void randomWait() {
        try {
            Thread.sleep(1000L + RANDOM.nextLong(1000L));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @NonNull
    @Override
    public Optional<Authentication> authenticate(@NonNull Authentication authentication) {
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            randomWait(); // to slowdown brute forcing
            if (authentication.getPrincipal().toString().equals(this.username)
                    && BCrypt.checkpw(authentication.getCredentials().toString(), Secret.toString(this.secret))) {
                List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
                grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
                if (isNotBlank(group)) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(group));
                }
                UsernamePasswordAuthenticationToken token =
                        new UsernamePasswordAuthenticationToken(username, "", grantedAuthorities);
                SecurityContextHolder.getContext().setAuthentication(token);
                OicUserDetails userDetails = new OicUserDetails(username, grantedAuthorities);
                SecurityListener.fireAuthenticated2(userDetails);
                return Optional.of(token);
            } else {
                throw new BadCredentialsException("Wrong username and password: " + authentication);
            }
        }
        return Optional.empty();
    }

    @Extension
    public static class DescriptorImpl extends OicPropertyDescriptor {
        @Override
        public boolean isApplicable() {
            return !FIPS140.useCompliantAlgorithms();
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Escape Hatch";
        }
    }

    /**
     * Excluding the escapeHatch login from CSRF protection as the crumb is calculated based on the authentication
     * mirroring behavior of the normal login page.
     *
     * @author Michael Bischoff
     */
    @Extension
    public static class CrumbExclusionImpl extends CrumbExclusion {

        @Override
        public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            String pathInfo = request.getPathInfo();
            if ("/securityRealm/escapeHatch".equals(pathInfo)) {
                chain.doFilter(request, response);
                return true;
            }
            return false;
        }
    }
}
