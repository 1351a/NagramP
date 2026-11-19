/*
 * This is a source file of Nagram.
 * It is licensed under GNU GPL v. 3 or later.
 */

package org.telegram.utils.proxy.vless;

import android.net.Uri;
import android.text.TextUtils;

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

    /** Parses a {@code vless://} sharing link. Returns null for anything unsupported. */
    public static VlessProfile parse(String link) {
        if (TextUtils.isEmpty(link) || !link.regionMatches(true, 0, "vless://", 0, 8)) {
            return null;
        }
        try {
            Uri uri = Uri.parse(link.trim());
            String host = uri.getHost();
            int port = uri.getPort();
            String uuid = uri.getUserInfo();
            if (TextUtils.isEmpty(host) || port <= 0 || TextUtils.isEmpty(uuid)) {
                return null;
            }
            String type = uri.getQueryParameter("type");
            if (!TextUtils.isEmpty(type) && !"ws".equalsIgnoreCase(type)) {
                return null;
            }
            String encryption = uri.getQueryParameter("encryption");
            if (!TextUtils.isEmpty(encryption) && !"none".equalsIgnoreCase(encryption)) {
                return null;
            }
            String security = uri.getQueryParameter("security");
            boolean tls = TextUtils.isEmpty(security) || "tls".equalsIgnoreCase(security);
            String sni = uri.getQueryParameter("sni");
            if (TextUtils.isEmpty(sni)) {
                sni = uri.getQueryParameter("peer");
            }
            String wsHost = uri.getQueryParameter("host");
            String path = uri.getQueryParameter("path");
            String label = uri.getFragment();
            VlessProfile profile = new VlessProfile(label, host, port, uuid, sni, wsHost, path, tls);
            return profile.isValid() ? profile : null;
        } catch (Exception ignore) {
            return null;
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
