/*
 * This is a source file of Nagram.
 * It is licensed under GNU GPL v. 3 or later.
 */

package org.telegram.utils.proxy.vless;

import android.os.Build;
import android.util.Log;
import android.util.Base64;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * One VLESS-over-WebSocket-over-TLS tunnel.
 *
 * <p>The wire format is the plain VLESS request header followed by a byte stream carried in
 * masked binary WebSocket frames. Frames from the peer may be fragmented, interleaved with
 * ping/close control frames, and the VLESS response header can land in its own frame, so the
 * decoder strips it exactly once before handing payload bytes to the caller.
 */
final class VlessTunnel implements Closeable {

    private static final String TAG = "NagramVLESS";
    private static final int CONNECT_TIMEOUT_MS = 10000;
    private static final int MAX_CONNECT_ADDRESSES = 3;
    private static final int WRITE_CHUNK = 32 * 1024;
    private static final int MAX_MESSAGE = 4 * 1024 * 1024;
    private static final int MAX_HANDSHAKE_HEAD = 8192;

    private static final String USER_AGENT =
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
                    + "Chrome/120.0.0.0 Mobile Safari/537.36";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final VlessProfile profile;
    private final Socket plain;
    private final Socket transport;
    private final InputStream netIn;
    private final OutputStream netOut;
    private final Object writeLock = new Object();

    private byte[] buf = new byte[8192];
    private int bufLen;
    private byte[] requestHeader;
    private boolean requestHeaderSent;
    private boolean responseHeaderDone;
    private volatile boolean closed;

    private VlessTunnel(VlessProfile profile, Socket plain, Socket transport) throws IOException {
        this.profile = profile;
        this.plain = plain;
        this.transport = transport;
        this.netIn = new BufferedInputStream(transport.getInputStream(), 32 * 1024);
        this.netOut = transport.getOutputStream();
    }

    static VlessTunnel open(VlessProfile profile, String dstHost, int dstPort) throws IOException {
        Socket plain = null;
        try {
            plain = connectFirst(profile.address, profile.port);

            Socket transport = plain;
            if (profile.tls) {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, null, RANDOM);
                SSLSocketFactory factory = ctx.getSocketFactory();
                SSLSocket tls = (SSLSocket) factory.createSocket(plain, profile.sni, profile.port, true);
                SSLParameters params = tls.getSSLParameters();
                if (Build.VERSION.SDK_INT >= 24) {
                    params.setServerNames(Collections.singletonList(new SNIHostName(profile.sni)));
                    params.setEndpointIdentificationAlgorithm("HTTPS");
                }
                if (Build.VERSION.SDK_INT >= 29) {
                    params.setApplicationProtocols(new String[]{"http/1.1"});
                }
                tls.setSSLParameters(params);
                // TLS 1.3 ClientHello from Conscrypt is distinguishable from mainstream clients on
                // filtered networks; TLS 1.2 negotiates reliably and is what the WS upgrade needs.
                try {
                    tls.setEnabledProtocols(new String[]{"TLSv1.2"});
                } catch (Exception ignore) {
                }
                tls.setSoTimeout(CONNECT_TIMEOUT_MS);
                Log.d(TAG, "tls handshake to " + profile.address + ":" + profile.port
                        + " sni=" + profile.sni + " target=" + dstHost + ":" + dstPort);
                tls.startHandshake();
                Log.d(TAG, "tls ok proto=" + tls.getSession().getProtocol()
                        + " cipher=" + tls.getSession().getCipherSuite()
                        + " alpn=" + tls.getApplicationProtocol());
                transport = tls;
            }

            VlessTunnel tunnel = new VlessTunnel(profile, plain, transport);
            tunnel.wsHandshake();
            tunnel.writeVlessHeader(dstHost, dstPort);
            transport.setSoTimeout(0);
            return tunnel;
        } catch (IOException e) {
            closeQuietly(plain);
            throw e;
        } catch (Exception e) {
            closeQuietly(plain);
            throw new IOException("vless setup failed: " + e, e);
        }
    }

    private void wsHandshake() throws IOException {
        byte[] keyBytes = new byte[16];
        RANDOM.nextBytes(keyBytes);
        String request = "GET " + profile.wsPath + " HTTP/1.1\r\n"
                + "Host: " + profile.wsHost + "\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Key: " + Base64.encodeToString(keyBytes, Base64.NO_WRAP) + "\r\n"
                + "Sec-WebSocket-Version: 13\r\n"
                + "User-Agent: " + USER_AGENT + "\r\n\r\n";
        netOut.write(request.getBytes(StandardCharsets.ISO_8859_1));
        netOut.flush();

        StringBuilder head = new StringBuilder();
        int matched = 0;
        while (matched < 4) {
            int b = netIn.read();
            if (b < 0) {
                throw new IOException("ws handshake eof");
            }
            head.append((char) b);
            if ((matched == 0 && b == '\r') || (matched == 1 && b == '\n')
                    || (matched == 2 && b == '\r') || (matched == 3 && b == '\n')) {
                matched++;
            } else {
                matched = 0;
            }
            if (head.length() > MAX_HANDSHAKE_HEAD) {
                throw new IOException("ws handshake too long");
            }
        }
        Log.d(TAG, "ws request path=" + profile.wsPath + " host=" + profile.wsHost);
        int eol = head.indexOf("\r\n");
        String status = eol > 0 ? head.substring(0, eol) : head.toString();
        Log.d(TAG, "ws status: " + status);
        if (!status.contains(" 101 ")) {
            throw new IOException("ws upgrade rejected: " + status);
        }
    }

    private void writeVlessHeader(String dstHost, int dstPort) throws IOException {
        byte[] uuid = profile.uuidBytes();
        if (uuid == null) {
            throw new IOException("bad uuid");
        }
        ByteArrayOutputStream h = new ByteArrayOutputStream(48);
        h.write(0);
        h.write(uuid, 0, 16);
        h.write(0);
        h.write(1);
        h.write((dstPort >> 8) & 0xff);
        h.write(dstPort & 0xff);
        byte[] v4 = parseIpv4(dstHost);
        byte[] v6 = v4 == null ? parseIpv6(dstHost) : null;
        if (v4 != null) {
            h.write(1);
            h.write(v4, 0, 4);
        } else if (v6 != null) {
            h.write(3);
            h.write(v6, 0, 16);
        } else {
            byte[] host = dstHost.getBytes(StandardCharsets.US_ASCII);
            if (host.length == 0 || host.length > 255) {
                throw new IOException("bad destination host");
            }
            h.write(2);
            h.write(host.length);
            h.write(host, 0, host.length);
        }
        // The server only answers when the request header shares a WebSocket message with the
        // first payload chunk, so it is buffered here and flushed by write()/read().
        requestHeader = h.toByteArray();
    }

    /** Writes payload bytes to the peer. */
    void write(byte[] data, int off, int len) throws IOException {
        if (closed) {
            throw new IOException("tunnel closed");
        }
        if (!requestHeaderSent) {
            ByteArrayOutputStream combined = new ByteArrayOutputStream(64 + len);
            if (requestHeader != null) {
                combined.write(requestHeader, 0, requestHeader.length);
                requestHeader = null;
            }
            combined.write(data, off, len);
            requestHeaderSent = true;
            sendFrame(0x2, combined.toByteArray());
            return;
        }
        while (len > 0) {
            int chunk = Math.min(len, WRITE_CHUNK);
            byte[] copy = new byte[chunk];
            System.arraycopy(data, off, copy, 0, chunk);
            sendFrame(0x2, copy);
            off += chunk;
            len -= chunk;
        }
    }

    /** Reads payload bytes; returns -1 once the peer closed the tunnel. */
    int read(byte[] dst) throws IOException {
        if (!requestHeaderSent) {
            // Nothing to piggyback on; still send the header so the peer can open the stream.
            requestHeaderSent = true;
            byte[] header = requestHeader;
            requestHeader = null;
            if (header != null) {
                sendFrame(0x2, header);
            }
        }
        while (true) {
            if (bufLen > 0 && !responseHeaderDone) {
                if (bufLen >= 2) {
                    int addons = buf[1] & 0xff;
                    if (bufLen >= 2 + addons) {
                        responseHeaderDone = true;
                        int skip = 2 + addons;
                        System.arraycopy(buf, skip, buf, 0, bufLen - skip);
                        bufLen -= skip;
                    }
                }
            }
            if (responseHeaderDone && bufLen > 0) {
                int n = Math.min(bufLen, dst.length);
                System.arraycopy(buf, 0, dst, 0, n);
                System.arraycopy(buf, n, buf, 0, bufLen - n);
                bufLen -= n;
                return n;
            }
            byte[] msg = readMessage();
            if (msg == null) {
                return -1;
            }
            if (msg.length > 0) {
                appendToBuffer(msg);
            }
        }
    }

    private void appendToBuffer(byte[] msg) throws IOException {
        if (bufLen + msg.length > MAX_MESSAGE) {
            throw new IOException("tunnel buffer overflow");
        }
        if (bufLen + msg.length > buf.length) {
            int size = buf.length;
            while (size < bufLen + msg.length) {
                size <<= 1;
            }
            byte[] grown = new byte[size];
            System.arraycopy(buf, 0, grown, 0, bufLen);
            buf = grown;
        }
        System.arraycopy(msg, 0, buf, bufLen, msg.length);
        bufLen += msg.length;
    }

    private byte[] readMessage() throws IOException {
        ByteArrayOutputStream acc = null;
        while (true) {
            int b0 = netIn.read();
            if (b0 < 0) {
                return null;
            }
            int b1 = readByte();
            int opcode = b0 & 0x0f;
            boolean masked = (b1 & 0x80) != 0;
            long len = b1 & 0x7f;
            if (len == 126) {
                len = ((long) readByte() << 8) | readByte();
            } else if (len == 127) {
                len = 0;
                for (int i = 0; i < 8; i++) {
                    len = (len << 8) | readByte();
                }
            }
            if (len < 0 || len > MAX_MESSAGE) {
                throw new IOException("ws frame too large: " + len);
            }
            byte[] mask = null;
            if (masked) {
                mask = new byte[4];
                readFully(mask, 0, 4);
            }
            byte[] data = new byte[(int) len];
            readFully(data, 0, data.length);
            if (mask != null) {
                for (int i = 0; i < data.length; i++) {
                    data[i] ^= mask[i & 3];
                }
            }
            if (opcode == 0x8) {
                return null;
            }
            if (opcode == 0x9) {
                sendFrame(0xA, data);
                continue;
            }
            if (opcode == 0xA) {
                continue;
            }
            if (acc == null) {
                acc = new ByteArrayOutputStream(Math.max(64, data.length));
            }
            acc.write(data, 0, data.length);
            if ((b0 & 0x80) != 0) {
                break;
            }
        }
        return acc == null ? new byte[0] : acc.toByteArray();
    }

    private void sendFrame(int opcode, byte[] data) throws IOException {
        synchronized (writeLock) {
            if (closed) {
                throw new IOException("tunnel closed");
            }
            byte[] mask = new byte[4];
            RANDOM.nextBytes(mask);
            netOut.write(0x80 | opcode);
            int len = data.length;
            if (len < 126) {
                netOut.write(0x80 | len);
            } else if (len < 65536) {
                netOut.write(0x80 | 126);
                netOut.write((len >> 8) & 0xff);
                netOut.write(len & 0xff);
            } else {
                netOut.write(0x80 | 127);
                for (int i = 7; i >= 0; i--) {
                    netOut.write((int) (((long) len >> (8 * i)) & 0xff));
                }
            }
            netOut.write(mask, 0, 4);
            byte[] masked = new byte[len];
            for (int i = 0; i < len; i++) {
                masked[i] = (byte) (data[i] ^ mask[i & 3]);
            }
            netOut.write(masked, 0, len);
            netOut.flush();
        }
    }

    private int readByte() throws IOException {
        int b = netIn.read();
        if (b < 0) {
            throw new EOFException();
        }
        return b;
    }

    private void readFully(byte[] dst, int off, int len) throws IOException {
        while (len > 0) {
            int n = netIn.read(dst, off, len);
            if (n < 0) {
                throw new EOFException();
            }
            off += n;
            len -= n;
        }
    }

    @Override
    public void close() {
        closed = true;
        closeQuietly(transport);
        closeQuietly(plain);
    }

    private static void closeQuietly(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignore) {
            }
        }
    }

    /**
     * Connects using a fresh socket per address, IPv4 first.
     *
     * A timed-out connect leaves the socket unusable, so addresses must never share one.
     */
    private static Socket connectFirst(String host, int port) throws IOException {
        InetAddress[] all = InetAddress.getAllByName(host);
        if (all == null || all.length == 0) {
            throw new IOException("cannot resolve " + host);
        }
        List<InetAddress> order = new ArrayList<>();
        for (InetAddress address : all) {
            if (address instanceof Inet4Address) {
                order.add(address);
            }
        }
        for (InetAddress address : all) {
            if (!(address instanceof Inet4Address)) {
                order.add(address);
            }
        }
        IOException last = null;
        int attempts = 0;
        for (InetAddress address : order) {
            if (attempts++ >= MAX_CONNECT_ADDRESSES) {
                break;
            }
            Socket socket = new Socket();
            try {
                socket.setTcpNoDelay(true);
                socket.connect(new InetSocketAddress(address, port), CONNECT_TIMEOUT_MS);
                Log.d(TAG, "connected " + address.getHostAddress() + ":" + port);
                return socket;
            } catch (IOException e) {
                last = e;
                Log.w(TAG, "connect failed " + address.getHostAddress() + ":" + port + " " + e.getMessage());
                closeQuietly(socket);
            }
        }
        throw last != null ? last : new IOException("no address for " + host);
    }

    private static byte[] parseIpv4(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            if (parts[i].isEmpty() || parts[i].length() > 3) {
                return null;
            }
            for (int j = 0; j < parts[i].length(); j++) {
                if (!Character.isDigit(parts[i].charAt(j))) {
                    return null;
                }
            }
            int v = Integer.parseInt(parts[i]);
            if (v < 0 || v > 255) {
                return null;
            }
            out[i] = (byte) v;
        }
        return out;
    }

    private static byte[] parseIpv6(String host) {
        String value = host;
        if (value.startsWith("[") && value.endsWith("]")) {
            value = value.substring(1, value.length() - 1);
        }
        if (value.indexOf(':') < 0) {
            return null;
        }
        try {
            byte[] raw = InetAddress.getByName(value).getAddress();
            return raw.length == 16 ? raw : null;
        } catch (Exception ignore) {
            return null;
        }
    }
}
