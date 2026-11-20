/*
 * This is a source file of Nagram.
 * It is licensed under GNU GPL v. 3 or later.
 */

package org.telegram.utils.proxy.vless;

import android.util.Log;

import org.telegram.messenger.FileLog;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Local SOCKS5 endpoint that funnels every accepted CONNECT into a VLESS tunnel.
 *
 * <p>tgnet already speaks SOCKS5, so the whole Telegram stack (API, uploads, downloads) can be
 * routed through the configured node without touching native code.
 */
public final class VlessGateway {

    public static final int DEFAULT_PORT = 10808;

    private static final String TAG = "NagramVLESS";
    private static final int MAX_CONNECTIONS = 32;
    private static final int MAX_PARALLEL_HANDSHAKES = 3;
    private static final int REPLY_GENERAL_FAILURE = 0x01;
    private static final int REPLY_HOST_UNREACHABLE = 0x04;
    private static final int REPLY_COMMAND_UNSUPPORTED = 0x07;

    private final Semaphore slots = new Semaphore(MAX_CONNECTIONS);
    private final Semaphore handshakes = new Semaphore(MAX_PARALLEL_HANDSHAKES);
    private final Set<Socket> activeSockets = Collections.newSetFromMap(new ConcurrentHashMap<Socket, Boolean>());
    private final ExecutorService pool = Executors.newCachedThreadPool(new ThreadFactory() {
        private final AtomicInteger counter = new AtomicInteger();

        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r, "vless-gw-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    });

    private volatile boolean running;
    private volatile int port;
    private volatile VlessProfile profile;
    private ServerSocket serverSocket;
    private Thread acceptThread;

    public synchronized int start(VlessProfile newProfile, int desiredPort) {
        if (running && profile != null && newProfile != null && profile.address.equals(newProfile.address)
                && profile.port == newProfile.port && profile.uuid.equals(newProfile.uuid)) {
            return port;
        }
        stop();
        profile = newProfile;
        ServerSocket socket = null;
        try {
            socket = bind(desiredPort);
        } catch (IOException e) {
            FileLog.e("vless: cannot bind local port " + desiredPort, e);
            try {
                socket = bind(0);
            } catch (IOException second) {
                FileLog.e("vless: cannot bind ephemeral port", second);
            }
        }
        if (socket == null) {
            return 0;
        }
        serverSocket = socket;
        port = socket.getLocalPort();
        running = true;
        acceptThread = new Thread(this::acceptLoop, "vless-gw-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        FileLog.d("vless gateway listening on 127.0.0.1:" + port);
        return port;
    }

    public synchronized void stop() {
        running = false;
        closeQuietly(serverSocket);
        serverSocket = null;
        Thread thread = acceptThread;
        acceptThread = null;
        if (thread != null) {
            thread.interrupt();
        }
        for (Socket socket : activeSockets) {
            closeQuietly(socket);
        }
        activeSockets.clear();
        port = 0;
    }

    public int getPort() {
        return running ? port : 0;
    }

    public boolean isRunning() {
        return running && port > 0;
    }

    private static ServerSocket bind(int desiredPort) throws IOException {
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), desiredPort), 16);
        return socket;
    }

    private void acceptLoop() {
        while (running) {
            ServerSocket local = serverSocket;
            if (local == null) {
                return;
            }
            try {
                Socket client = local.accept();
                if (!slots.tryAcquire()) {
                    closeQuietly(client);
                    continue;
                }
                activeSockets.add(client);
                pool.execute(() -> handleClient(client));
            } catch (IOException e) {
                if (running) {
                    FileLog.e("vless: accept failed", e);
                }
                return;
            }
        }
    }

    private void handleClient(Socket client) {
        VlessTunnel tunnel = null;
        try {
            client.setTcpNoDelay(true);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();
            Socks5Request request = socks5Handshake(in, out);
            if (request == null) {
                return;
            }
            VlessProfile current = profile;
            if (current == null) {
                socks5Reply(out, REPLY_GENERAL_FAILURE);
                return;
            }
            // Cap concurrent TLS/WS handshakes: tgnet opens many sockets at once and each
            // handshake is CPU heavy, which starves the UI thread on slow devices.
            handshakes.acquire();
            try {
                tunnel = VlessTunnel.open(current, request.host, request.port);
            } finally {
                handshakes.release();
            }
            socks5Reply(out, 0x00);
            // Pull one chunk from the client so the VLESS header can ride along with it.
            byte[] first = new byte[16 * 1024];
            int firstLen;
            try {
                client.setSoTimeout(8000);
                firstLen = in.read(first);
            } finally {
                client.setSoTimeout(0);
            }
            if (firstLen < 0) {
                return;
            }
            tunnel.sendRequest(firstLen == 0 ? null : Arrays.copyOf(first, firstLen));
            pump(client, tunnel);
        } catch (IOException e) {
            FileLog.d("vless: tunnel failed: " + e.getMessage());
            Log.e(TAG, "tunnel failed", e);
        } catch (Throwable e) {
            FileLog.e("vless: tunnel crashed", e);
            Log.e(TAG, "tunnel crashed", e);
        } finally {
            if (tunnel != null) {
                tunnel.close();
            }
            closeQuietly(client);
            activeSockets.remove(client);
            slots.release();
        }
    }

    private static final class Socks5Request {
        final String host;
        final int port;

        Socks5Request(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    private Socks5Request socks5Handshake(InputStream in, OutputStream out) throws IOException {
        int version = in.read();
        if (version != 5) {
            return null;
        }
        int methodCount = in.read();
        if (methodCount <= 0) {
            return null;
        }
        byte[] methods = new byte[methodCount];
        readFully(in, methods);
        boolean noAuth = false;
        for (byte method : methods) {
            if (method == 0) {
                noAuth = true;
                break;
            }
        }
        if (!noAuth) {
            out.write(new byte[]{5, (byte) 0xFF});
            out.flush();
            return null;
        }
        out.write(new byte[]{5, 0});
        out.flush();

        int ver = in.read();
        int cmd = in.read();
        int rsv = in.read();
        int atyp = in.read();
        if (ver != 5 || rsv != 0) {
            return null;
        }
        if (cmd != 1) {
            socks5Reply(out, REPLY_COMMAND_UNSUPPORTED);
            return null;
        }
        String host;
        if (atyp == 1) {
            byte[] raw = new byte[4];
            readFully(in, raw);
            host = (raw[0] & 0xff) + "." + (raw[1] & 0xff) + "." + (raw[2] & 0xff) + "." + (raw[3] & 0xff);
        } else if (atyp == 3) {
            int len = in.read();
            if (len <= 0) {
                return null;
            }
            byte[] raw = new byte[len];
            readFully(in, raw);
            host = new String(raw, java.nio.charset.StandardCharsets.US_ASCII);
        } else if (atyp == 4) {
            byte[] raw = new byte[16];
            readFully(in, raw);
            try {
                host = InetAddress.getByAddress(raw).getHostAddress();
            } catch (Exception e) {
                socks5Reply(out, REPLY_HOST_UNREACHABLE);
                return null;
            }
        } else {
            socks5Reply(out, REPLY_HOST_UNREACHABLE);
            return null;
        }
        int hi = in.read();
        int lo = in.read();
        if (hi < 0 || lo < 0) {
            return null;
        }
        int dstPort = (hi << 8) | lo;
        return dstPort > 0 ? new Socks5Request(host, dstPort) : null;
    }

    private void socks5Reply(OutputStream out, int code) throws IOException {
        out.write(new byte[]{5, (byte) code, 0, 1, 0, 0, 0, 0, 0, 0});
        out.flush();
    }

    private void pump(Socket client, VlessTunnel tunnel) {
        Thread up = new Thread(() -> {
            byte[] buffer = new byte[16 * 1024];
            try {
                InputStream in = client.getInputStream();
                int n;
                while ((n = in.read(buffer)) > 0) {
                    tunnel.write(buffer, 0, n);
                }
            } catch (IOException ignore) {
            } finally {
                tunnel.close();
                closeQuietly(client);
            }
        }, "vless-gw-up");
        up.setDaemon(true);
        up.start();

        byte[] buffer = new byte[16 * 1024];
        try {
            OutputStream out = client.getOutputStream();
            int n;
            while ((n = tunnel.read(buffer)) > 0) {
                out.write(buffer, 0, n);
                out.flush();
            }
        } catch (IOException ignore) {
        } finally {
            tunnel.close();
            closeQuietly(client);
        }
    }

    private static void readFully(InputStream in, byte[] dst) throws IOException {
        int off = 0;
        while (off < dst.length) {
            int n = in.read(dst, off, dst.length - off);
            if (n < 0) {
                throw new IOException("socks5 eof");
            }
            off += n;
        }
    }

    private static void closeQuietly(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignore) {
            }
        }
    }
}
