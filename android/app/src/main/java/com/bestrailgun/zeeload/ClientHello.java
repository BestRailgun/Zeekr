package com.bestrailgun.zeeload;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

final class ClientHello {
    final String host; final byte[] raw;
    ClientHello(String h, byte[] r) { host = h; raw = r; }
    static ClientHello read(InputStream in) throws IOException {
        ByteArrayOutputStream raw = new ByteArrayOutputStream(), handshake = new ByteArrayOutputStream();
        int required = -1;
        while (required < 0 || handshake.size() < required) {
            byte[] header = exact(in, 5);
            int n = u16(header, 3);
            if (header[0] != 22 || header[1] != 3 || n < 1 || n > 18432 || raw.size() + n > 131072) throw new IOException("不是受支持的 TLS ClientHello");
            byte[] record = exact(in, n); raw.write(header); raw.write(record); handshake.write(record);
            if (handshake.size() >= 4 && required < 0) {
                byte[] b = handshake.toByteArray();
                if (b[0] != 1) throw new IOException("缺少 ClientHello");
                required = 4 + ((b[1] & 255) << 16) + ((b[2] & 255) << 8) + (b[3] & 255);
                if (required > 131072) throw new IOException("ClientHello 过大");
            }
        }
        return new ClientHello(host(handshake.toByteArray()), raw.toByteArray());
    }
    static String host(byte[] b) throws IOException {
        try {
            int p = 4 + 2 + 32;
            p += 1 + (b[p] & 255);
            p += 2 + u16(b, p);
            p += 1 + (b[p] & 255);
            if (p == b.length) throw new IOException("连接没有 SNI，无法透明转发");
            int end = p + 2 + u16(b, p); p += 2;
            if (end > b.length) throw new IOException("TLS 扩展长度错误");
            while (p + 4 <= end) {
                int type = u16(b, p), len = u16(b, p + 2); p += 4;
                if (p + len > end) throw new IOException("TLS 扩展越界");
                if (type == 0) {
                    int q = p + 2, namesEnd = p + 2 + u16(b, p);
                    if (namesEnd > p + len) throw new IOException("SNI 长度错误");
                    while (q + 3 <= namesEnd) {
                        int nameType = b[q] & 255, n = u16(b, q + 1); q += 3;
                        if (q + n > namesEnd) throw new IOException("SNI 越界");
                        if (nameType == 0) {
                            String h = new String(b, q, n, StandardCharsets.US_ASCII).toLowerCase(Locale.US);
                            if (!h.matches("(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?") || h.contains("..")) throw new IOException("SNI 域名无效");
                            return h;
                        }
                        q += n;
                    }
                }
                p += len;
            }
            throw new IOException("连接没有可用的 SNI");
        } catch (IndexOutOfBoundsException e) { throw new IOException("ClientHello 不完整", e); }
    }
    private static int u16(byte[] b, int p) { return ((b[p] & 255) << 8) | (b[p + 1] & 255); }
    static byte[] exact(InputStream in, int n) throws IOException {
        byte[] b = new byte[n]; int p = 0, k;
        while (p < n && (k = in.read(b, p, n - p)) != -1) p += k;
        if (p != n) throw new EOFException("连接提前结束"); return b;
    }
}
