/*
 * This is a source file of Nagram.
 * It is licensed under GNU GPL v. 3 or later.
 */

package org.telegram.utils.proxy.vless;

import android.text.TextUtils;

import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Immutable description of one VLESS node taken from a subscription.
 * The node is never shown to the user; only the transport uses it.
 */
public final class VlessProfile {

    public final String label;
    public final String address;
    public final int port;
    public final String uuid;
    public final String sni;
    public final String wsHost;
    public final String wsPath;
    public final boolean tls;

    public VlessProfile(String label, String address, int port, String uuid,
                        String sni, String wsHost, String wsPath, boolean tls) {
        this.label = label == null ? "" : label;
        this.address = address;
        this.port = port;
        this.uuid = uuid;
        this.sni = TextUtils.isEmpty(sni) ? address : sni;
        this.wsHost = TextUtils.isEmpty(wsHost) ? this.sni : wsHost;
        this.wsPath = TextUtils.isEmpty(wsPath) ? "/" : wsPath;
        this.tls = tls;
    }

    public boolean isValid() {
        return !TextUtils.isEmpty(address) && port > 0 && port <= 65535 && uuidBytes() != null;
    }

    public byte[] uuidBytes() {
        if (TextUtils.isEmpty(uuid)) {
            return null;
        }
        String hex = uuid.replace("-", "");
        if (hex.length() != 32) {
            return null;
        }
        byte[] out = new byte[16];
        try {
            for (int i = 0; i < 16; i++) {
                out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (NumberFormatException e) {
            return null;
        }
        return out;
    }

    /**
     * Parses a {@code vless://} sharing link.
     *
     * Android's Uri does not reliably expose authority parts for unknown schemes, so the link is
     * split by hand: {@code vless://uuid@host:port?query#label}.
     */
    public static VlessProfile parse(String link) {
        if (TextUtils.isEmpty(link)) {
            return null;
        }
        String value = link.trim();
        if (!value.regionMatches(true, 0, "vless://", 0, 8)) {
            return null;
        }
        value = value.substring(8);

        String label = null;
        int hash = value.indexOf('#');
        if (hash >= 0) {
            label = decode(value.substring(hash + 1));
            value = value.substring(0, hash);
        }

        String query = null;
        int qm = value.indexOf('?');
        if (qm >= 0) {
            query = value.substring(qm + 1);
            value = value.substring(0, qm);
        }

        int at = value.lastIndexOf('@');
        if (at <= 0) {
            return null;
        }
        String uuid = decode(value.substring(0, at));
        String hostPort = value.substring(at + 1);

        String host;
        int port;
        if (hostPort.startsWith("[")) {
            int close = hostPort.indexOf(']');
            if (close < 0) {
                return null;
            }
            host = hostPort.substring(1, close);
            int colon = hostPort.indexOf(':', close);
            if (colon < 0) {
                return null;
            }
            port = parseInt(hostPort.substring(colon + 1));
        } else {
            int colon = hostPort.lastIndexOf(':');
            if (colon <= 0) {
                return null;
            }
            host = hostPort.substring(0, colon);
            port = parseInt(hostPort.substring(colon + 1));
        }
        if (TextUtils.isEmpty(host) || port <= 0 || port > 65535 || TextUtils.isEmpty(uuid)) {
            return null;
        }

        Map<String, String> params = new HashMap<>();
        if (query != null) {
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                if (eq < 0) {
                    params.put(decode(pair).toLowerCase(Locale.US), "");
                } else {
                    params.put(decode(pair.substring(0, eq)).toLowerCase(Locale.US),
                            decode(pair.substring(eq + 1)));
                }
            }
        }

        String type = params.get("type");
        if (!TextUtils.isEmpty(type) && !"ws".equalsIgnoreCase(type)) {
            return null;
        }
        String encryption = params.get("encryption");
        if (!TextUtils.isEmpty(encryption) && !"none".equalsIgnoreCase(encryption)) {
            return null;
        }
        String security = params.get("security");
        boolean tls = TextUtils.isEmpty(security) || "tls".equalsIgnoreCase(security);
        String sni = params.get("sni");
        if (TextUtils.isEmpty(sni)) {
            sni = params.get("peer");
        }
        String wsHost = params.get("host");
        String path = params.get("path");

        VlessProfile profile = new VlessProfile(label, host, port, uuid, sni, wsHost, path, tls);
        return profile.isValid() ? profile : null;
    }

    private static int parseInt(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception e) {
            return -1;
        }
    }

    private static String decode(String value) {
        if (TextUtils.isEmpty(value)) {
            return "";
        }
        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (Exception e) {
            return value;
        }
    }

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("label", label);
        o.put("address", address);
        o.put("port", port);
        o.put("uuid", uuid);
        o.put("sni", sni);
        o.put("ws_host", wsHost);
        o.put("ws_path", wsPath);
        o.put("tls", tls);
        return o;
    }

    public static VlessProfile fromJson(String raw) {
        if (TextUtils.isEmpty(raw)) {
            return null;
        }
        try {
            JSONObject o = new JSONObject(raw);
            VlessProfile profile = new VlessProfile(
                    o.optString("label"),
                    o.optString("address"),
                    o.optInt("port"),
                    o.optString("uuid"),
                    o.optString("sni"),
                    o.optString("ws_host"),
                    o.optString("ws_path"),
                    o.optBoolean("tls", true));
            return profile.isValid() ? profile : null;
        } catch (JSONException ignore) {
            return null;
        }
    }

    @Override
    public String toString() {
        return "vless[" + address + ":" + port + "]";
    }
}
