/*
 * This is a source file of Nagram.
 * It is licensed under GNU GPL v. 3 or later.
 */

package org.telegram.utils.proxy.vless;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
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
    private static final int MAX_BYTES = 256 * 1024;
    private static final String USER_AGENT =
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
                    + "Chrome/120.0.0.0 Mobile Safari/537.36";

    private VlessSubscriptionClient() {
    }

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", Context.MODE_PRIVATE);
    }

    public static VlessProfile loadCached() {
        try {
            return VlessProfile.fromJson(prefs().getString(PREF_KEY, null));
        } catch (Throwable e) {
            return null;
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
            VlessProfile parsed = parseNodes(decode(body));
            if (parsed != null) {
                saveCached(parsed);
                return parsed;
            }
            FileLog.d("vless: subscription has no matching node");
        } catch (Throwable e) {
            FileLog.d("vless: subscription refresh failed: " + e.getMessage());
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

    private static VlessProfile parseNodes(String text) {
        VlessProfile byAddress = null;
        VlessProfile byLooseLabel = null;
        for (String line : text.split("[\\r\\n]+")) {
            String link = line.trim();
            if (link.isEmpty() || !link.regionMatches(true, 0, "vless://", 0, 8)) {
                continue;
            }
            VlessProfile profile = VlessProfile.parse(link);
            if (profile == null) {
                continue;
            }
            String label = profile.label.toLowerCase(Locale.US);
            String address = profile.address.toLowerCase(Locale.US);
            if (TARGET_LABEL.equals(label) || TARGET_LABEL.equals(address)) {
                return profile;
            }
            if (byAddress == null && address.contains(TARGET_LABEL)) {
                byAddress = profile;
            }
            if (byLooseLabel == null && label.contains(TARGET_LABEL)) {
                byLooseLabel = profile;
            }
        }
        return byAddress != null ? byAddress : byLooseLabel;
    }
}
