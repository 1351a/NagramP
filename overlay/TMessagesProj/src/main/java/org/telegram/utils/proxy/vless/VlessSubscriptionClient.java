/*
 * This is a source file of Nagram.
 * It is licensed under GNU GPL v. 3 or later.
 */

package org.telegram.utils.proxy.vless;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Log;
import android.util.Base64;

import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Pulls the VLESS subscription and keeps the single node we need.
 *
 * <p>The subscription is refreshed once per app start. The selected node is persisted only in
 * app-private preferences; nothing about it is ever surfaced in the UI.
 */
public final class VlessSubscriptionClient {

    /** Endpoint the app refreshes on every start. */
    public static final String SUBSCRIPTION_URL =
            "https://vless1.130chang.eu.org/d19a38ec-8add-47d7-b45a-7a07b248e4bb";

    /** Node we route through. */
    public static final String TARGET_LABEL = "japan.com";

    private static final String PREF_KEY = "cdn_vless_profile";
    private static final String TAG = "NagramCDN";
    private static final int MAX_BYTES = 256 * 1024;
    // The subscription serves a Clash YAML to browser agents and a base64 vless list to
    // client agents; we need the latter.
    private static final String USER_AGENT = "v2rayNG/1.8.5";

    /** Last-resort node so the channel still works before the first refresh succeeds. */
    private static final VlessProfile BUILT_IN = new VlessProfile(
            "time.is", "time.is", 443,
            "d19a38ec-8add-47d7-b45a-7a07b248e4bb",
            "vless1.130chang.eu.org", "vless1.130chang.eu.org", "/?ed=2560", true);

    private VlessSubscriptionClient() {
    }

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", Context.MODE_PRIVATE);
    }

    public static VlessProfile loadCached() {
        try {
            VlessProfile cached = VlessProfile.fromJson(prefs().getString(PREF_KEY, null));
            return cached != null ? cached : BUILT_IN;
        } catch (Throwable e) {
            return BUILT_IN;
        }
    }

    private static void saveCached(VlessProfile profile) {
        try {
            prefs().edit().putString(PREF_KEY, profile.toJson().toString()).apply();
        } catch (Throwable e) {
            FileLog.e("vless: cannot cache profile", e);
        }
    }

    /**
     * Downloads and parses the subscription, caching the selected node.
     * Returns the cached profile when the download or the parse produced nothing.
     */
    public static VlessProfile refresh() {
        VlessProfile cached = loadCached();
        try {
            String body = download();
            Log.d(TAG, "subscription body len=" + (body == null ? -1 : body.length()));
            String decoded = decode(body);
            Log.d(TAG, "decoded len=" + decoded.length() + " hasVless=" + decoded.contains("vless://"));
            VlessProfile parsed = parseNodes(decoded);
            Log.d(TAG, "picked=" + parsed);
            if (parsed != null) {
                saveCached(parsed);
                return parsed;
            }
            FileLog.d("vless: subscription has no matching node");
        } catch (Throwable e) {
            FileLog.d("vless: subscription refresh failed: " + e.getMessage());
            Log.e(TAG, "subscription refresh failed", e);
        }
        return cached;
    }

    private static String download() throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(SUBSCRIPTION_URL).openConnection();
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(15000);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("User-Agent", USER_AGENT);
        connection.setRequestProperty("Accept", "*/*");
        connection.setRequestProperty("Accept-Encoding", "identity");
        connection.setInstanceFollowRedirects(true);
        try {
            int code = connection.getResponseCode();
            Log.d(TAG, "subscription HTTP " + code);
            if (code < 200 || code >= 300) {
                throw new IOException("HTTP " + code);
            }
            try (InputStream in = connection.getInputStream()) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int n;
                while ((n = in.read(buffer)) > 0) {
                    out.write(buffer, 0, n);
                    if (out.size() > MAX_BYTES) {
                        break;
                    }
                }
                return new String(out.toByteArray(), StandardCharsets.UTF_8);
            }
        } finally {
            connection.disconnect();
        }
    }

    private static String decode(String body) {
        if (TextUtils.isEmpty(body)) {
            return "";
        }
        String compact = body.replaceAll("\\s", "");
        if (compact.isEmpty()) {
            return "";
        }
        try {
            String decoded = new String(Base64.decode(compact, Base64.DEFAULT), StandardCharsets.UTF_8);
            if (decoded.contains("vless://")) {
                return decoded;
            }
        } catch (Throwable ignore) {
        }
        try {
            String decoded = new String(Base64.decode(compact, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING), StandardCharsets.UTF_8);
            if (decoded.contains("vless://")) {
                return decoded;
            }
        } catch (Throwable ignore) {
        }
        return body;
    }

    /**
     * Picks the best node from the subscription.
     *
     * Port 443 matters more than the label here: carriers routinely reset TLS on non-standard
     * ports, so a 2053 node fails to handshake on many networks while the same subscription's
     * 443 nodes work. Preference order: 443 + target label, any 443 node, target label, first.
     */
    private static VlessProfile parseNodes(String text) {
        java.util.List<VlessProfile> all = new java.util.ArrayList<>();
        VlessProfile targetPort443 = null;
        VlessProfile anyPort443 = null;
        VlessProfile targetAnyPort = null;
        for (String line : text.split("[\\r\\n]+")) {
            String link = line.trim();
            if (link.isEmpty() || !link.regionMatches(true, 0, "vless://", 0, 8)) {
                continue;
            }
            VlessProfile profile = VlessProfile.parse(link);
            if (profile == null) {
                continue;
            }
            all.add(profile);
            String label = profile.label.toLowerCase(Locale.US);
            String address = profile.address.toLowerCase(Locale.US);
            boolean isTarget = TARGET_LABEL.equals(label) || TARGET_LABEL.equals(address)
                    || address.contains(TARGET_LABEL);
            if (profile.port == 443) {
                if (isTarget && targetPort443 == null) {
                    targetPort443 = profile;
                }
                if (anyPort443 == null) {
                    anyPort443 = profile;
                }
            } else if (isTarget && targetAnyPort == null) {
                targetAnyPort = profile;
            }
        }
        StringBuilder log = new StringBuilder("nodes=").append(all.size());
        for (VlessProfile p : all) {
            log.append(' ').append(p.address).append(':').append(p.port);
        }
        Log.d(TAG, log.toString());
        if (targetPort443 != null) {
            return targetPort443;
        }
        if (anyPort443 != null) {
            return anyPort443;
        }
        if (targetAnyPort != null) {
            return targetAnyPort;
        }
        return all.isEmpty() ? null : all.get(0);
    }
}
