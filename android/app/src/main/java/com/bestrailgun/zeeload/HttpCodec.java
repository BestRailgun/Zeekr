package com.bestrailgun.zeeload;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

final class HttpCodec {
    static final int BODY_LIMIT = 4 * 1024 * 1024;
    static final class Request {
        String method, path; final Map<String, String> headers = new LinkedHashMap<>(); byte[] body;
    }
    static Request read(InputStream in, OutputStream out) throws IOException {
        String first = line(in); if (first == null) return null;
        String[] split = first.split(" ");
        if (split.length != 3 || !split[0].matches("[A-Z]+") || !split[2].matches("HTTP/1\\.[01]")) throw new IOException("不支持的 HTTP 请求");
        Request req = new Request(); req.method = split[0]; req.path = split[1];
        int length = first.length(); String line;
        while ((line = line(in)) != null && !line.isEmpty()) {
            length += line.length(); if (length > 65536) throw new IOException("HTTP 头过大");
            int i = line.indexOf(':'); if (i <= 0) throw new IOException("HTTP 头无效");
            String key = line.substring(0, i).toLowerCase(Locale.US), value = line.substring(i + 1).trim();
            if (!key.matches("[a-z0-9!#$%&'*+.^_`|~-]+")) throw new IOException("HTTP 头名称无效");
            if ((key.equals("content-length") || key.equals("transfer-encoding") || key.equals("host")) && req.headers.containsKey(key)) throw new IOException("重复的 HTTP 边界头");
            req.headers.merge(key, value, (a, b) -> a + (key.equals("cookie") ? "; " : ", ") + b);
        }
        if (line == null) throw new EOFException("HTTP 头未结束");
        String transfer = req.headers.get("transfer-encoding"), size = req.headers.get("content-length");
        if (transfer != null && size != null) throw new IOException("HTTP 边界冲突");
        if ("100-continue".equalsIgnoreCase(req.headers.get("expect"))) { out.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.US_ASCII)); out.flush(); }
        if (transfer != null) {
            if (!transfer.equalsIgnoreCase("chunked")) throw new IOException("不支持的传输编码");
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            while (true) {
                String h = line(in); if (h == null) throw new EOFException();
                int count;
                try { count = Integer.parseInt(h.split(";", 2)[0].trim(), 16); } catch (NumberFormatException e) { throw new IOException("分块长度无效", e); }
                if (count < 0 || count > BODY_LIMIT - body.size()) throw new IOException("请求体过大");
                if (count == 0) {
                    int trailers = 0;
                    do { h = line(in); if (h == null) throw new EOFException(); trailers += h.length() + 2; if (trailers > 65536) throw new IOException("尾部头过大"); } while (!h.isEmpty());
                    break;
                }
                body.write(ClientHello.exact(in, count)); if (!"".equals(line(in))) throw new IOException("分块结尾无效");
            }
            req.body = body.toByteArray();
        } else {
            long n;
            try { n = size == null ? 0 : Long.parseLong(size); } catch (NumberFormatException e) { throw new IOException("请求体长度无效", e); }
            if (n < 0 || n > BODY_LIMIT) throw new IOException("请求体过大"); req.body = ClientHello.exact(in, (int)n);
        }
        return req;
    }
    static String line(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(); int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') { byte[] a = b.toByteArray(); if (a.length == 0 || a[a.length - 1] != '\r') throw new IOException("HTTP 换行无效"); return new String(a, 0, a.length - 1, StandardCharsets.ISO_8859_1); }
            b.write(c); if (b.size() > 16384) throw new IOException("HTTP 行过长");
        }
        if (b.size() != 0) throw new EOFException("HTTP 行未结束"); return null;
    }
    static void header(OutputStream out, int status, String reason, Map<String, String> headers) throws IOException {
        StringBuilder s = new StringBuilder("HTTP/1.1 " + status + " " + reason + "\r\n");
        for (Map.Entry<String, String> h : headers.entrySet()) s.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
        s.append("Connection: close\r\n\r\n"); out.write(s.toString().getBytes(StandardCharsets.ISO_8859_1)); out.flush();
    }
    private HttpCodec() { }
}
