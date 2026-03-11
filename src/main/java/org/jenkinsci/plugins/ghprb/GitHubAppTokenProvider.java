package org.jenkinsci.plugins.ghprb;

import hudson.ProxyConfiguration;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Generates and caches GitHub App installation access tokens.
 *
 * <p>Implements the full GitHub App authentication flow:
 * PEM private key → RS256-signed JWT → POST to GitHub API → installation access token.
 * Tokens are cached and automatically refreshed before expiry.</p>
 */
public final class GitHubAppTokenProvider {

    private static final Logger LOGGER = Logger.getLogger(GitHubAppTokenProvider.class.getName());

    private static final int JWT_EXPIRY_SECONDS = 600;

    private static final long TOKEN_REFRESH_BUFFER_MS = 300000L;

    private static final int HTTP_CREATED = 201;

    private static final int CONNECT_TIMEOUT = 10000;

    private static final int READ_TIMEOUT = 10000;

    private static final String PKCS1_HEADER = "-----BEGIN RSA PRIVATE KEY-----";

    private static final String PKCS1_FOOTER = "-----END RSA PRIVATE KEY-----";

    private static final String PKCS8_HEADER = "-----BEGIN PRIVATE KEY-----";

    private static final String PKCS8_FOOTER = "-----END PRIVATE KEY-----";

    // CHECKSTYLE:OFF
    private static final byte[] RSA_ALGORITHM_IDENTIFIER = {
        0x30, 0x0d,
        0x06, 0x09,
        0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00
    };

    private static final byte DER_SEQUENCE_TAG = 0x30;

    private static final byte DER_OCTET_STRING_TAG = 0x04;

    private static final byte[] DER_VERSION_ZERO = {0x02, 0x01, 0x00};

    private static final int DER_SHORT_FORM_LIMIT = 0x80;

    private static final int DER_TWO_BYTE_LIMIT = 0x100;

    private static final int DER_THREE_BYTE_LIMIT = 0x10000;
    // CHECKSTYLE:ON

    private final String appId;

    private final String installationId;

    private final String serverAPIUrl;

    private final PrivateKey privateKey;

    private String cachedToken;

    private long tokenExpiresAt;

    public GitHubAppTokenProvider(
            String appId,
            String installationId,
            String privateKeyPem,
            String serverAPIUrl
    ) throws IOException, GeneralSecurityException {
        this.appId = appId;
        this.installationId = installationId;
        this.serverAPIUrl = normalizeUrl(serverAPIUrl);
        this.privateKey = parsePrivateKey(privateKeyPem);
    }

    /**
     * Returns a valid installation access token, refreshing if needed.
     * Thread-safe: callers may invoke this concurrently.
     */
    public synchronized String getToken() throws IOException {
        if (cachedToken != null && System.currentTimeMillis() < tokenExpiresAt - TOKEN_REFRESH_BUFFER_MS) {
            return cachedToken;
        }
        refreshToken();
        return cachedToken;
    }

    /**
     * Clears the cached token, forcing a fresh exchange on the next {@link #getToken()} call.
     */
    public synchronized void invalidate() {
        cachedToken = null;
        tokenExpiresAt = 0;
    }

    private void refreshToken() throws IOException {
        String jwt = generateJwt();
        String url = serverAPIUrl + "/app/installations/" + installationId + "/access_tokens";

        LOGGER.log(Level.FINE, "Requesting new GitHub App installation token from {0}", url);

        HttpURLConnection conn = (HttpURLConnection) ProxyConfiguration.open(new URL(url));
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Authorization", "Bearer " + jwt);
            conn.setRequestProperty("Accept", "application/vnd.github+json");
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            conn.setReadTimeout(READ_TIMEOUT);
            conn.setDoOutput(true);

            OutputStream os = conn.getOutputStream();
            os.close();

            int responseCode = conn.getResponseCode();
            if (responseCode != HTTP_CREATED) {
                String error = readStream(conn.getErrorStream());
                throw new IOException(
                        "GitHub App token request failed (HTTP " + responseCode + "): " + error
                );
            }

            String responseBody = readStream(conn.getInputStream());
            JSONObject json = JSONObject.fromObject(responseBody);
            cachedToken = json.getString("token");
            String expiresAt = json.getString("expires_at");
            tokenExpiresAt = parseIso8601(expiresAt);

            LOGGER.log(Level.INFO, "Obtained GitHub App installation token (expires at {0})", expiresAt);
        } finally {
            conn.disconnect();
        }
    }

    private String generateJwt() {
        try {
            long nowSeconds = System.currentTimeMillis() / 1000L;
            long expSeconds = nowSeconds + JWT_EXPIRY_SECONDS;

            String header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
            String payload = "{\"iss\":\""
                    + appId + "\",\"iat\":" + nowSeconds + ",\"exp\":" + expSeconds + "}";

            String encodedHeader = base64UrlEncode(header.getBytes("UTF-8"));
            String encodedPayload = base64UrlEncode(payload.getBytes("UTF-8"));
            String signingInput = encodedHeader + "." + encodedPayload;

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(signingInput.getBytes("UTF-8"));
            byte[] signatureBytes = sig.sign();

            return signingInput + "." + base64UrlEncode(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JWT for GitHub App", e);
        }
    }

    static PrivateKey parsePrivateKey(String pem) throws GeneralSecurityException {
        boolean isPkcs1 = pem.contains(PKCS1_HEADER);

        String base64Content = pem
                .replace(PKCS1_HEADER, "")
                .replace(PKCS1_FOOTER, "")
                .replace(PKCS8_HEADER, "")
                .replace(PKCS8_FOOTER, "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.decodeBase64(base64Content);

        if (isPkcs1) {
            decoded = convertPkcs1ToPkcs8(decoded);
        }

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    /**
     * Wraps a PKCS#1 RSA private key inside a PKCS#8 PrivateKeyInfo structure
     * so it can be consumed by {@link KeyFactory}.
     */
    private static byte[] convertPkcs1ToPkcs8(byte[] pkcs1) {
        byte[] octetString = wrapInDerTag(DER_OCTET_STRING_TAG, pkcs1);
        byte[] innerContent = concatenateArrays(DER_VERSION_ZERO, RSA_ALGORITHM_IDENTIFIER, octetString);
        return wrapInDerTag(DER_SEQUENCE_TAG, innerContent);
    }

    private static byte[] wrapInDerTag(byte tag, byte[] content) {
        byte[] lengthBytes = derEncodeLength(content.length);
        byte[] result = new byte[1 + lengthBytes.length + content.length];
        result[0] = tag;
        System.arraycopy(lengthBytes, 0, result, 1, lengthBytes.length);
        System.arraycopy(content, 0, result, 1 + lengthBytes.length, content.length);
        return result;
    }

    // CHECKSTYLE:OFF
    private static byte[] derEncodeLength(int length) {
        if (length < DER_SHORT_FORM_LIMIT) {
            return new byte[]{(byte) length};
        } else if (length < DER_TWO_BYTE_LIMIT) {
            return new byte[]{(byte) 0x81, (byte) length};
        } else if (length < DER_THREE_BYTE_LIMIT) {
            return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) length};
        } else {
            return new byte[]{(byte) 0x83, (byte) (length >> 16), (byte) (length >> 8), (byte) length};
        }
    }
    // CHECKSTYLE:ON

    private static byte[] concatenateArrays(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) {
            total += a.length;
        }
        byte[] result = new byte[total];
        int offset = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, offset, a.length);
            offset += a.length;
        }
        return result;
    }

    private static String base64UrlEncode(byte[] data) {
        return Base64.encodeBase64URLSafeString(data);
    }

    private static String normalizeUrl(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static long parseIso8601(String dateStr) throws IOException {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            return sdf.parse(dateStr).getTime();
        } catch (ParseException e) {
            throw new IOException("Failed to parse token expiry date: " + dateStr, e);
        }
    }

    private static String readStream(InputStream stream) throws IOException {
        if (stream == null) {
            return "";
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(stream, "UTF-8"));
        try {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        } finally {
            reader.close();
        }
    }
}
