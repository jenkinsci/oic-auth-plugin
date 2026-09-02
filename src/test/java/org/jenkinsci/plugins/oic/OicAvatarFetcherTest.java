package org.jenkinsci.plugins.oic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import org.jenkinsci.plugins.oic.OicAvatarProperty.AvatarData;
import org.junit.jupiter.api.Test;

class OicAvatarFetcherTest {

    @Test
    void fetchesSupportedImageWithAccessToken() throws Exception {
        HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(connection.getContentType()).thenReturn("image/PNG; charset=binary");
        when(connection.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[] {1, 2, 3}));

        AvatarData data = fetcher(connection).fetch("https://example.org/me/photo", "access-token");

        assertEquals("image/png", data.contentType());
        assertArrayEquals(new byte[] {1, 2, 3}, data.bytes());
        verify(connection).setRequestProperty("Authorization", "Bearer access-token");
        verify(connection).setInstanceFollowRedirects(false);
    }

    @Test
    void doesNotSendAccessTokenOverPlainHttp() throws Exception {
        HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(connection.getContentType()).thenReturn("image/jpeg");
        when(connection.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[] {1}));

        assertEquals(
                "image/jpeg",
                fetcher(connection)
                        .fetch("http://example.org/avatar.jpg", "access-token")
                        .contentType());
        verify(connection, never()).setRequestProperty(org.mockito.ArgumentMatchers.eq("Authorization"), any());
    }

    @Test
    void rejectsUnsupportedContentType() throws Exception {
        HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(connection.getContentType()).thenReturn("image/svg+xml");

        assertNull(fetcher(connection).fetch("https://example.org/avatar.svg", null));
    }

    @Test
    void rejectsMissingContentType() throws Exception {
        HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(connection.getContentType()).thenReturn(" ");

        assertNull(fetcher(connection).fetch("https://example.org/avatar.png", null));
    }

    @Test
    void decodesInlineDataUrlsWithoutConnecting() throws Exception {
        ProxyAwareResourceRetriever retriever = mock(ProxyAwareResourceRetriever.class);

        AvatarData data = new OicAvatarFetcher(retriever).fetch("data:image/png;base64,AQID", null);

        assertEquals("image/png", data.contentType());
        assertArrayEquals(new byte[] {1, 2, 3}, data.bytes());
        verify(retriever, never()).openHTTPConnection(any());
    }

    @Test
    void rejectsUnsupportedProtocolsAndInvalidUrls() throws Exception {
        ProxyAwareResourceRetriever retriever = mock(ProxyAwareResourceRetriever.class);
        OicAvatarFetcher fetcher = new OicAvatarFetcher(retriever);

        assertNull(fetcher.fetch("file:///etc/passwd", null));
        assertNull(fetcher.fetch("data:image/png;base64,not-base64", null));
        assertNull(fetcher.fetch("not a url", null));
        verify(retriever, never()).openHTTPConnection(any());
    }

    @Test
    void rejectsNonSuccessfulEmptyAndOversizedResponses() throws Exception {
        HttpURLConnection connection = mock(HttpURLConnection.class);
        when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_NOT_FOUND);
        OicAvatarFetcher fetcher = fetcher(connection);
        assertNull(fetcher.fetch("https://example.org/avatar.png", null));

        when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(connection.getContentType()).thenReturn("image/png");
        when(connection.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
        assertNull(fetcher.fetch("https://example.org/avatar.png", null));

        when(connection.getInputStream())
                .thenReturn(new ByteArrayInputStream(new byte[OicAvatarProperty.AvatarImage.MAX_SIZE + 1]));
        assertNull(fetcher.fetch("https://example.org/avatar.png", null));
    }

    @Test
    void handlesConnectionFailure() throws Exception {
        ProxyAwareResourceRetriever retriever = mock(ProxyAwareResourceRetriever.class);
        when(retriever.openHTTPConnection(any())).thenThrow(new IOException("connection failed"));

        assertNull(new OicAvatarFetcher(retriever).fetch("https://example.org/avatar.png", "token"));
    }

    private static OicAvatarFetcher fetcher(HttpURLConnection connection) throws IOException {
        ProxyAwareResourceRetriever retriever = mock(ProxyAwareResourceRetriever.class);
        when(retriever.openHTTPConnection(any())).thenReturn(connection);
        return new OicAvatarFetcher(retriever);
    }
}
