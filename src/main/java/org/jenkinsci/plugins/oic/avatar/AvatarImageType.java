package org.jenkinsci.plugins.oic.avatar;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * The image types we are willing to download and serve as a user avatar.
 *
 * <p>
 * The type is determined solely by sniffing the leading magic bytes of the downloaded content. The
 * {@code Content-Type} declared by the identity provider is deliberately <strong>not</strong> trusted; the sniffed
 * type is authoritative both for the accept/reject decision and for the {@code Content-Type} we later serve back to
 * the browser.
 * <p>
 * We intentionally do <strong>not</strong> decode the image (for example with {@code ImageIO}) in order to validate
 * it: decoding untrusted images on the controller would expose it to decompression bombs. The intended guarantee is
 * instead the combination of a hard size cap on the download, this magic byte allow list, and
 * {@code X-Content-Type-Options: nosniff} on the response we serve.
 */
@Restricted(NoExternalUse.class)
public enum AvatarImageType {
    // The magic byte prefixes are written inline here rather than as named constants because enum constants must be
    // the first members of an enum declaration and so can not reference static fields declared below them.
    // Please do not "tidy" these into constants.

    /** {@code GIF87a} or {@code GIF89a}. */
    GIF("image/gif", "gif", new byte[] {0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, new byte[] {
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61
    }),
    /** JPEG start of image marker followed by the first marker of a segment. */
    JPEG("image/jpeg", "jpg", new byte[] {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF}),
    /** The PNG signature. */
    PNG("image/png", "png", new byte[] {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A});

    /**
     * The value of the {@code Accept} header to send when requesting an avatar, listing exactly the types we accept.
     */
    private static final String ACCEPT_HEADER_VALUE =
            Stream.of(values()).map(AvatarImageType::getContentType).collect(Collectors.joining(", "));

    private final String contentType;
    private final String fileExtension;
    private final byte[][] magicPrefixes;

    AvatarImageType(String contentType, String fileExtension, byte[]... magicPrefixes) {
        this.contentType = contentType;
        this.fileExtension = fileExtension;
        // defensive copy: the prefixes are never exposed, so this array can not be mutated after construction
        this.magicPrefixes = new byte[magicPrefixes.length][];
        for (int i = 0; i < magicPrefixes.length; i++) {
            this.magicPrefixes[i] = magicPrefixes[i].clone();
        }
    }

    /**
     * The MIME type to serve this image as.
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * The file extension (without a leading dot) to store this image as.
     */
    public String getFileExtension() {
        return fileExtension;
    }

    /**
     * Determine the image type of the given content by inspecting its leading bytes.
     *
     * @param data the content to inspect, may be {@code null}
     * @return the matching type, or {@code null} if the content is {@code null}, too short, or not one of the
     *         supported types
     */
    @CheckForNull
    public static AvatarImageType sniff(@CheckForNull byte[] data) {
        if (data == null) {
            return null;
        }
        for (AvatarImageType type : values()) {
            for (byte[] prefix : type.magicPrefixes) {
                if (data.length >= prefix.length && Arrays.equals(data, 0, prefix.length, prefix, 0, prefix.length)) {
                    return type;
                }
            }
        }
        return null;
    }

    /**
     * The value to send in the {@code Accept} header when downloading an avatar.
     */
    public static String acceptHeaderValue() {
        return ACCEPT_HEADER_VALUE;
    }
}
