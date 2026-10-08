package org.jenkinsci.plugins.oic.avatar;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.ProxyConfiguration;
import hudson.init.Terminator;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.util.DaemonThreadFactory;
import hudson.util.NamingThreadFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import jenkins.util.SystemProperties;
import org.jenkinsci.plugins.oic.OicCredentials;
import org.jenkinsci.plugins.oic.ssl.IgnoringHostNameVerifier;
import org.jenkinsci.plugins.oic.ssl.TLSUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Downloads user avatars off the login request thread. Enqueueing never blocks and never throws,
 * so a slow or broken provider can never slow down or fail a login.
 */
@Extension
@Restricted(NoExternalUse.class)
public class AvatarDownloadService {

    private static final Logger LOGGER = Logger.getLogger(AvatarDownloadService.class.getName());

    /** Hard cap on the size of an avatar we are willing to download and store. */
    public static final long MAX_SIZE_BYTES = 5L * 1024 * 1024;

    @SuppressWarnings("boxing")
    private static final int CONNECT_TIMEOUT_MS = SystemProperties.getInteger("OIC_AVATAR_CONNECT_TIMEOUT_MS", 2_000);

    @SuppressWarnings("boxing")
    private static final int READ_TIMEOUT_MS = SystemProperties.getInteger("OIC_AVATAR_READ_TIMEOUT_MS", 5_000);

    /** how often {@link #awaitIdle(Duration)} re-checks for outstanding downloads. */
    private static final long IDLE_POLL_INTERVAL_MS = 50L;

    private final ThreadPoolExecutor executor;

    /**
     * Downloads accepted but not yet finished. Tracked explicitly rather than derived from the executor: a task that has
     * been taken off the queue but is not yet counted as active would otherwise make {@link #awaitIdle(Duration)} report
     * idle while a download is still in flight.
     */
    private final AtomicInteger outstanding = new AtomicInteger();

    /**
     * Required for {@link Extension} instantiation; use {@link #get()} to obtain the singleton.
     */
    public AvatarDownloadService() {
        ThreadFactory threadFactory = new NamingThreadFactory(new DaemonThreadFactory(), "oic-auth avatar download");
        // if we can not keep up then we silently drop the download. Shedding an avatar is strictly better than
        // back-pressuring (or failing) a login, and the next login will simply try again.
        executor = new ThreadPoolExecutor(
                0, 4, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(100), threadFactory, (r, e) -> {
                    outstanding.decrementAndGet();
                    LOGGER.fine("Discarding an avatar download: the queue is full");
                });
    }

    public static AvatarDownloadService get() {
        return ExtensionList.lookupSingleton(AvatarDownloadService.class);
    }

    /**
     * Schedule the download of a user's avatar. Returns immediately and never throws.
     *
     * @param userId the id of the user the avatar belongs to
     * @param avatarUrl the {@code picture} claim URL to download from
     * @param useAccessToken whether the user's OIDC access token should be presented to the provider
     * @param disableSslVerification whether TLS certificate validation should be skipped
     */
    public void enqueue(
            @NonNull String userId, @NonNull String avatarUrl, boolean useAccessToken, boolean disableSslVerification) {
        outstanding.incrementAndGet();
        try {
            executor.execute(() -> {
                try {
                    run(userId, avatarUrl, useAccessToken, disableSslVerification);
                } finally {
                    outstanding.decrementAndGet();
                }
            });
        } catch (RejectedExecutionException e) {
            // a full queue is handled by the rejected execution handler, so in practice this only happens once the
            // executor has been shut down
            outstanding.decrementAndGet();
            LOGGER.log(Level.FINE, e, () -> "Not downloading the avatar for user " + userId + ": task rejected");
        }
    }

    private void run(String userId, String avatarUrl, boolean useAccessToken, boolean disableSslVerification) {
        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) { // we write the user record
            User user = User.getById(userId, false); // re-resolve; never hold a User across threads
            if (user == null) {
                return;
            }
            try {
                byte[] data = download(user, avatarUrl, useAccessToken, disableSslVerification);
                AvatarImageType type = AvatarImageType.sniff(data);
                if (type == null) {
                    throw new UnusableAvatarException("content is not gif, jpeg or png");
                }
                AvatarProperty.store(user, avatarUrl, type, data);
            } catch (UnusableAvatarException e) {
                reject(user, avatarUrl, e.getMessage());
            } catch (Exception e) { // must not escape into the executor
                // something transient: a connection failure, a timeout, a 5xx, an expired token... whatever avatar the
                // user already has was validated when it was stored, so keep it rather than making it flap.
                LOGGER.log(
                        Level.WARNING,
                        e,
                        () -> "Could not download the avatar for user " + user.getId() + " from " + avatarUrl
                                + "; keeping the existing avatar, if any");
            }
        }
    }

    /**
     * Log why an avatar is unusable and drop any avatar the user may still have, so that the UI falls back to
     * Jenkins' default person icon rather than showing a stale avatar.
     * <p>
     * There is deliberately no fallback to letting the browser fetch the provider URL directly: the administrator
     * chose a mode where the image is only ever served by Jenkins.
     */
    private void reject(@NonNull User user, @NonNull String url, @CheckForNull String reason) {
        LOGGER.warning(() -> "Not storing the avatar for user " + user.getId() + " from " + url + ": " + reason);
        try {
            AvatarProperty.clear(user);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, e, () -> "Could not clear the avatar of user " + user.getId());
        }
    }

    /**
     * The provider served something we will never accept, as opposed to a transient failure. Any avatar the user
     * currently has is dropped.
     */
    private static class UnusableAvatarException extends IOException {
        private static final long serialVersionUID = 1L;

        UnusableAvatarException(String message) {
            super(message);
        }
    }

    /**
     * Download the avatar, enforcing the scheme allow list and the size cap.
     *
     * @return the downloaded bytes; the caller is responsible for sniffing the image type
     */
    private byte[] download(
            @NonNull User user, @NonNull String avatarUrl, boolean useAccessToken, boolean disableSslVerification)
            throws Exception {
        URI uri = new URI(avatarUrl);
        String scheme = uri.getScheme();
        // only plain http(s) to a real host: no file:, jar:, data: or anything else
        boolean https = "https".equalsIgnoreCase(scheme);
        if (uri.getHost() == null || !(https || "http".equalsIgnoreCase(scheme))) {
            throw new UnusableAvatarException("refusing to download an avatar from " + avatarUrl);
        }

        String bearerToken = null;
        if (useAccessToken) {
            if (https) {
                // read the token at download time rather than at login time so that a refreshed token is used
                OicCredentials credentials = user.getProperty(OicCredentials.class);
                String accessToken = credentials == null ? null : credentials.getAccessToken();
                if (accessToken != null && !accessToken.isEmpty()) {
                    bearerToken = accessToken;
                }
            } else {
                LOGGER.warning(() -> "Not sending the access token of user " + user.getId() + " to " + avatarUrl
                        + " as it would be sent in clear text; requesting the avatar anonymously");
            }
        }

        // HttpURLConnection rather than java.net.http.HttpClient: HttpClient forcibly re-applies the "HTTPS" endpoint
        // identification algorithm, so hostname verification cannot be turned off per client (only by the global
        // jdk.internal.httpclient.disableHostnameVerification property), which would make disableSslVerification only
        // half honoured. This is also what ProxyAwareResourceRetriever and CustomOidcConfiguration do.
        @SuppressWarnings("deprecation")
        HttpURLConnection connection = (HttpURLConnection) ProxyConfiguration.open(uri.toURL());
        try {
            if (disableSslVerification && connection instanceof HttpsURLConnection secureConnection) {
                secureConnection.setSSLSocketFactory(TLSUtils.createAnythingGoesSSLSocketFactory());
                // an all trusting TrustManager is not enough, the hostname is checked separately
                secureConnection.setHostnameVerifier(IgnoringHostNameVerifier.INSTANCE);
            }
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            // same protocol redirects are followed; a cross protocol redirect is never followed, which conveniently
            // rules out an https -> http downgrade
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("Accept", AvatarImageType.acceptHeaderValue());
            if (bearerToken != null) {
                connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
            }

            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                String message = "got HTTP " + status + " from " + avatarUrl;
                // "not found" and "gone" are definitive answers, anything else (a 5xx, a rejected token, ...) may
                // succeed next time
                throw status == HttpURLConnection.HTTP_NOT_FOUND || status == HttpURLConnection.HTTP_GONE
                        ? new UnusableAvatarException(message)
                        : new IOException(message);
            }
            // logged for diagnostics only: the declared content type is never acted upon, the sniffed magic bytes are
            // what decide whether we accept the content and what we later serve it as
            LOGGER.log(Level.FINE, () -> "Avatar at " + avatarUrl + " was declared as " + connection.getContentType());

            // a declared length that is too big lets us reject before reading any of the body
            long declaredLength = connection.getContentLengthLong();
            if (declaredLength > MAX_SIZE_BYTES) {
                throw new UnusableAvatarException("avatar at " + avatarUrl + " declares a length of " + declaredLength
                        + " bytes which exceeds the maximum of " + MAX_SIZE_BYTES + " bytes");
            }

            try (InputStream in = connection.getInputStream()) {
                // Content-Length is not trusted, so read one byte more than we allow and check what we actually got
                byte[] data = in.readNBytes((int) MAX_SIZE_BYTES + 1);
                if (data.length > MAX_SIZE_BYTES) {
                    throw new UnusableAvatarException(
                            "avatar at " + avatarUrl + " exceeds the maximum size of " + MAX_SIZE_BYTES + " bytes");
                }
                return data;
            }
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Wait until there is no queued or running download. Visible for testing.
     *
     * @param timeout how long to wait
     * @return {@code true} if the service became idle, {@code false} if the timeout expired first
     */
    @Restricted(NoExternalUse.class)
    public boolean awaitIdle(@NonNull Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            if (outstanding.get() == 0) {
                return true;
            }
            if (System.nanoTime() - deadline >= 0) {
                return false;
            }
            Thread.sleep(IDLE_POLL_INTERVAL_MS);
        }
    }

    @Terminator
    public void shutdown() {
        executor.shutdownNow();
    }
}
