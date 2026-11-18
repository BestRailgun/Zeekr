package com.bestrailgun.zeeload;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.GZIPInputStream;
import okhttp3.*;

final class ProxyServer implements Closeable {
    private final Certificates certificates;
    private final MetadataEngine metadata;
    private final String carIp;
    private final ExecutorService workers = new ThreadPoolExecutor(0, 32, 30, TimeUnit.SECONDS, new SynchronousQueue<>());
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private final OkHttpClient upstream = new OkHttpClient.Builder().proxy(Proxy.NO_PROXY)
        .connectTimeout(20, TimeUnit.SECONDS).readTimeout(60, TimeUnit.SECONDS).callTimeout(180, TimeUnit.SECONDS)
        .followRedirects(false).followSslRedirects(false).protocols(Collections.singletonList(Protocol.HTTP_1_1)).build();
    private final ServerSocket listener = new ServerSocket();
    private volatile boolean closed;
    ProxyServer(Certificates cert, MetadataEngine engine, String ip) throws IOException { certificates = cert; metadata = engine; carIp = ip; }
    void start() throws IOException {
        listener.setReuseAddress(true); listener.bind(new InetSocketAddress("0.0.0.0", RootRules.PORT), 32);
        Thread accept = new Thread(() -> {
            while (!closed) {
                try {
                    Socket socket = listener.accept();
                    if (!socket.getInetAddress().getHostAddress().equals(carIp)) { socket.close(); continue; }
                    socket.setSoTimeout(60000); socket.setTcpNoDelay(true); sockets.add(socket);
                    try { workers.execute(() -> handle(socket)); }
                    catch (RejectedExecutionException e) { sockets.remove(socket); socket.close(); State.log("连接数达到上限，请稍后重试"); }
                } catch (IOException e) { if (!closed) State.log("监听异常：" + e.getMessage()); }
            }
        }, "zeeload-listener"); accept.setDaemon(true); accept.start();
    }
    private void handle(Socket socket) {
        String host = "TLS";
        try (Socket ignored = socket) {
            ClientHello hello = ClientHello.read(socket.getInputStream()); host = hello.host;
            State.connections.incrementAndGet();
            if (!MetadataEngine.allowedHost(host)) { tunnel(socket, hello); return; }
            try (TlsChannel channel = new TlsChannel(socket, certificates.engine(host), hello.raw)) {
                InputStream in = new BufferedInputStream(channel.input, 32768); OutputStream out = new BufferedOutputStream(channel.output, 32768);
                HttpCodec.Request req = HttpCodec.read(in, out); if (req == null) return;
                String authority = req.headers.getOrDefault("host", host);
                if (!authority.equalsIgnoreCase(host) && !authority.equalsIgnoreCase(host + ":443")) throw new IOException("HTTP Host 与 TLS 域名不一致");
                String url;
                if (req.path.startsWith("/")) url = "https://" + host + req.path;
                else {
                    URI absolute = new URI(req.path);
                    if (!"https".equalsIgnoreCase(absolute.getScheme()) || !host.equalsIgnoreCase(absolute.getHost()) || (absolute.getPort() != -1 && absolute.getPort() != 443)) throw new IOException("请求地址不匹配");
                    url = req.path;
                }
                if (metadata.replacementAllowed(url) && (req.method.equals("GET") || req.method.equals("HEAD"))) serveApk(req, out);
                else forward(req, url, out);
                out.flush();
            }
        } catch (Exception e) {
            if (!closed) State.log(host + " · " + e.getClass().getSimpleName() + ": " + Objects.toString(e.getMessage(), "连接关闭"));
        } finally { sockets.remove(socket); }
    }
    private void serveApk(HttpCodec.Request req, OutputStream out) throws IOException {
        ApkInfo apk = metadata.apk; ByteRange range;
        Map<String, String> headers = new LinkedHashMap<>(); headers.put("Accept-Ranges", "bytes"); headers.put("Cache-Control", "no-store");
        headers.put("Content-Type", "application/vnd.android.package-archive"); headers.put("ETag", "\"" + apk.sha256 + "\"");
        String requestedRange = req.headers.get("range"), ifRange = req.headers.get("if-range");
        if (ifRange != null && !ifRange.equals(headers.get("ETag"))) requestedRange = null;
        try { range = ByteRange.parse(requestedRange, apk.size); }
        catch (IllegalArgumentException e) { headers.put("Content-Range", "bytes */" + apk.size); headers.put("Content-Length", "0"); HttpCodec.header(out, 416, "Range Not Satisfiable", headers); return; }
        headers.put("Content-Length", Long.toString(range.length()));
        if (range.partial) headers.put("Content-Range", "bytes " + range.start + "-" + range.end + "/" + apk.size);
        HttpCodec.header(out, range.partial ? 206 : 200, range.partial ? "Partial Content" : "OK", headers);
        if (req.method.equals("HEAD")) return;
        State.status("正在传输 APK", "请保持手机热点开启，等待车机完成下载");
        try (RandomAccessFile file = new RandomAccessFile(apk.file, "r")) {
            file.seek(range.start); long left = range.length(); byte[] buf = new byte[128 * 1024];
            while (left > 0) {
                int n = file.read(buf, 0, (int)Math.min(buf.length, left)); if (n < 0) throw new EOFException("APK 文件被截断");
                out.write(buf, 0, n); left -= n; State.bytes.addAndGet(n);
            }
        }
        out.flush(); State.status("本次下载请求已发送", "请在车机确认安装结果；分段下载可能还有后续请求");
    }
    private static final Set<String> HOP = new HashSet<>(Arrays.asList("connection", "proxy-connection", "proxy-authorization", "proxy-authenticate", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade"));
    private void forward(HttpCodec.Request req, String url, OutputStream out) throws IOException {
        Request.Builder builder = new Request.Builder().url(url);
        Set<String> excluded = new HashSet<>(HOP);
        for (String h : req.headers.getOrDefault("connection", "").split(",")) excluded.add(h.trim().toLowerCase(Locale.US));
        req.headers.forEach((k, v) -> { if (!excluded.contains(k) && !k.equals("content-length") && !k.equals("expect") && !k.equals("accept-encoding")) builder.addHeader(k, v); });
        builder.header("Accept-Encoding", "identity");
        RequestBody body = (req.body.length > 0 || Arrays.asList("POST", "PUT", "PATCH", "PROPPATCH", "REPORT").contains(req.method)) ? RequestBody.create(MediaType.parse(req.headers.getOrDefault("content-type", "application/octet-stream")), req.body) : null;
        builder.method(req.method, body);
        try (Response response = upstream.newCall(builder.build()).execute()) {
            ResponseBody rb = response.body();
            Map<String, String> headers = new LinkedHashMap<>(); Set<String> skip = new HashSet<>(HOP);
            for (String h : response.header("Connection", "").split(",")) skip.add(h.trim().toLowerCase(Locale.US));
            for (String key : response.headers().names()) if (!skip.contains(key.toLowerCase(Locale.US)) && !key.equalsIgnoreCase("Content-Length")) headers.put(key, response.header(key));
            boolean json = response.header("Content-Type", "").toLowerCase(Locale.US).contains("json");
            if (json && rb != null && rb.contentLength() <= HttpCodec.BODY_LIMIT && !req.method.equals("HEAD")) {
                InputStream stream = rb.byteStream();
                if ("gzip".equalsIgnoreCase(response.header("Content-Encoding"))) stream = new GZIPInputStream(stream);
                else if (response.header("Content-Encoding") != null && !"identity".equalsIgnoreCase(response.header("Content-Encoding"))) { streamResponse(response, req, headers, rb.byteStream(), out); return; }
                ByteArrayOutputStream prefix = new ByteArrayOutputStream(); byte[] b = new byte[32768]; int n;
                while (prefix.size() <= HttpCodec.BODY_LIMIT && (n = stream.read(b)) != -1) prefix.write(b, 0, n);
                removeHeader(headers, "Content-Encoding");
                if (prefix.size() > HttpCodec.BODY_LIMIT) {
                    HttpCodec.header(out, response.code(), response.message(), headers); prefix.writeTo(out); copy(stream, out); return;
                }
                String text = new String(prefix.toByteArray(), StandardCharsets.UTF_8), rewritten = metadata.rewrite(text);
                byte[] bytes = rewritten.getBytes(StandardCharsets.UTF_8);
                if (!rewritten.equals(text)) {
                    for (String name : Arrays.asList("ETag", "Content-MD5", "Digest", "Content-Range", "Last-Modified")) removeHeader(headers, name);
                    headers.put("Cache-Control", "no-store");
                }
                headers.put("Content-Length", Integer.toString(bytes.length));
                HttpCodec.header(out, response.code(), response.message(), headers); out.write(bytes);
            } else { streamResponse(response, req, headers, rb == null ? null : rb.byteStream(), out); }
        }
    }
    private void streamResponse(Response response, HttpCodec.Request req, Map<String, String> headers, InputStream in, OutputStream out) throws IOException {
        String length = response.header("Content-Length"); if (length != null) headers.put("Content-Length", length);
        HttpCodec.header(out, response.code(), response.message(), headers);
        if (in != null && !req.method.equals("HEAD") && response.code() != 204 && response.code() != 304) copy(in, out);
    }
    private static void removeHeader(Map<String, String> headers, String key) { headers.keySet().removeIf(k -> k.equalsIgnoreCase(key)); }
    private void tunnel(Socket client, ClientHello hello) throws Exception {
        Socket remote = new Socket(); sockets.add(remote);
        try (Socket ignored = remote) {
            // Non-target TLS is forwarded unchanged; system DNS and original peer perform TLS validation.
            remote.connect(new InetSocketAddress(hello.host, 443), 20000); remote.setSoTimeout(60000);
            OutputStream upstreamOut = remote.getOutputStream(); upstreamOut.write(hello.raw); upstreamOut.flush();
            Thread request = new Thread(() -> { try { copy(client.getInputStream(), upstreamOut); remote.shutdownOutput(); } catch (IOException ignoredError) { } }, "tls-passthrough"); request.setDaemon(true); request.start();
            copy(remote.getInputStream(), client.getOutputStream());
        } finally { sockets.remove(remote); }
    }
    private static void copy(InputStream in, OutputStream out) throws IOException { byte[] b = new byte[64 * 1024]; int n; while ((n = in.read(b)) != -1) { out.write(b, 0, n); out.flush(); } }
    @Override public void close() {
        closed = true; try { listener.close(); } catch (IOException ignored) { }
        for (Socket s : sockets) try { s.close(); } catch (IOException ignored) { }
        workers.shutdownNow(); upstream.dispatcher().cancelAll(); upstream.connectionPool().evictAll();
    }
}
