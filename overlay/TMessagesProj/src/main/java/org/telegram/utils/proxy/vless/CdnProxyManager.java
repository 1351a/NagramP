/*
 * This is a source file of Nagram.
 * It is licensed under GNU GPL v. 3 or later.
 */

package org.telegram.utils.proxy.vless;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.NotificationCenter;
import org.telegram.messenger.SharedConfig;
import org.telegram.tgnet.ConnectionsManager;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Owns the lifetime of the built-in "Cloudflare CDN" channel: refresh the subscription once per
 * app start, keep the local gateway alive, and tell tgnet where to connect.
 */
public final class CdnProxyManager {

    private static final String PREF_ENABLED = "cdn_proxy_enabled";
    private static final String TAG = "NagramCDN";

    private static final VlessGateway GATEWAY = new VlessGateway();
    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor(new ThreadFactory() {
        private final AtomicInteger counter = new AtomicInteger();

        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r, "vless-worker-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    });

    private static volatile boolean enabled;
    private static volatile VlessProfile profile;
    private static volatile boolean bootstrapped;

    private CdnProxyManager() {
    }

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", Context.MODE_PRIVATE);
    }

    /** Called once from ApplicationLoader: restores state, binds the gateway, refreshes subscription. */
    public static synchronized void bootstrap() {
        if (bootstrapped) {
            return;
        }
        bootstrapped = true;
        try {
            enabled = prefs().getBoolean(PREF_ENABLED, true);
            profile = VlessSubscriptionClient.loadCached();
            Log.d(TAG, "bootstrap enabled=" + enabled + " cached=" + profile);
            if (profile != null) {
                publish(GATEWAY.start(profile, VlessGateway.DEFAULT_PORT));
            }
            Log.d(TAG, "bootstrap port=" + SharedConfig.cdnProxyPort + " active=" + SharedConfig.cdnProxyActive);
        } catch (Throwable e) {
            FileLog.e("vless: bootstrap failed", e);
            Log.e(TAG, "bootstrap failed", e);
            enabled = false;
            publish(0);
        }
        try {
            WORKER.execute(() -> refreshInternal(false));
        } catch (Throwable e) {
            FileLog.e("vless: cannot schedule refresh", e);
        }
    }

    /** Mirrors gateway state into SharedConfig so hot paths never touch this class. */
    private static void publish(int port) {
        SharedConfig.cdnProxyPort = port;
        SharedConfig.cdnProxyActive = enabled && port > 0;
    }

    private static void refreshInternal(boolean forceNotify) {
        try {
            VlessProfile refreshed = VlessSubscriptionClient.refresh();
            Log.d(TAG, "refresh result=" + refreshed);
            if (refreshed == null) {
                return;
            }
            profile = refreshed;
            if (!enabled) {
                return;
            }
            int before = GATEWAY.getPort();
            int port = GATEWAY.start(refreshed, VlessGateway.DEFAULT_PORT);
            publish(port);
            Log.d(TAG, "gateway port=" + port + " enabled=" + enabled);
            if (port > 0 && (forceNotify || before != port || !ConnectionsManager.isProxyUsingCdn())) {
                notifyTgnet();
            }
        } catch (Throwable e) {
            FileLog.e("vless: refresh failed", e);
        }
    }

    /** True when the channel is selected and actually serving. */
    public static boolean isEnabled() {
        return SharedConfig.cdnProxyActive;
    }

    /** True when the user wants the channel on, regardless of gateway state. */
    public static boolean isWanted() {
        return enabled;
    }

    public static int getPort() {
        return SharedConfig.cdnProxyPort;
    }

    /** Kicks a subscription refresh + gateway start without waiting. */
    public static void refreshInBackground() {
        try {
            WORKER.execute(() -> refreshInternal(true));
        } catch (Throwable e) {
            FileLog.e("vless: cannot schedule refresh", e);
        }
    }

    /** UI toggle. Applies immediately and re-points tgnet. */
    public static void setEnabled(boolean value) {
        try {
            enabled = value;
            prefs().edit().putBoolean(PREF_ENABLED, value).apply();
            if (value) {
                VlessProfile current = profile;
                if (current == null) {
                    refreshInBackground();
                    publish(0);
                } else {
                    publish(GATEWAY.start(current, VlessGateway.DEFAULT_PORT));
                }
            } else {
                GATEWAY.stop();
                publish(0);
            }
            final boolean fallback = !value
                    && MessagesController.getGlobalMainSettings().getBoolean("proxy_enabled", false)
                    && SharedConfig.currentProxy != null;
            ConnectionsManager.setProxySettings(value || fallback,
                    fallback ? SharedConfig.currentProxy.settings : null);
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged);
        } catch (Throwable e) {
            FileLog.e("vless: toggle failed", e);
        }
    }

    private static void notifyTgnet() {
        try {
            ConnectionsManager.setProxySettings(true, null);
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged);
        } catch (Throwable e) {
            FileLog.e("vless: cannot rebind tgnet", e);
        }
    }
}
