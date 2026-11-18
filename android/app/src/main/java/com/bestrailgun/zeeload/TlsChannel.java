package com.bestrailgun.zeeload;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;

/** SSLEngine preserves already-read ClientHello bytes without hidden socket APIs. */
final class TlsChannel implements Closeable {
    private final Socket socket;
    private final SSLEngine engine;
    private final InputStream wireIn;
    private final OutputStream wireOut;
    private final ByteBuffer netIn = ByteBuffer.allocate(262144), netOut = ByteBuffer.allocate(65536), appIn = ByteBuffer.allocate(65536);
    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0).asReadOnlyBuffer();
    TlsChannel(Socket s, SSLEngine e, byte[] replay) throws IOException {
        socket = s; engine = e;
        wireIn = new SequenceInputStream(new ByteArrayInputStream(replay), s.getInputStream());
        wireOut = s.getOutputStream(); netIn.limit(0); appIn.limit(0);
        engine.beginHandshake(); handshake();
    }
    private void tasks() { Runnable r; while ((r = engine.getDelegatedTask()) != null) r.run(); }
    private void receive() throws IOException {
        netIn.compact();
        if (!netIn.hasRemaining()) throw new SSLException("TLS record 过大");
        int n = wireIn.read(netIn.array(), netIn.position(), netIn.remaining());
        if (n < 0) throw new EOFException("TLS 连接关闭");
        netIn.position(netIn.position() + n); netIn.flip();
    }
    private SSLEngineResult wrap(ByteBuffer src) throws IOException {
        netOut.clear(); SSLEngineResult r = engine.wrap(src, netOut);
        if (r.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) throw new SSLException("TLS 输出缓冲不足");
        if (netOut.position() > 0) { wireOut.write(netOut.array(), 0, netOut.position()); wireOut.flush(); }
        if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) tasks();
        return r;
    }
    private void handshake() throws IOException {
        int idle = 0;
        while (true) {
            SSLEngineResult.HandshakeStatus h = engine.getHandshakeStatus();
            if (h == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || h == SSLEngineResult.HandshakeStatus.FINISHED) return;
            if (h == SSLEngineResult.HandshakeStatus.NEED_TASK) { tasks(); continue; }
            if (h == SSLEngineResult.HandshakeStatus.NEED_WRAP) { wrap(EMPTY.duplicate()); continue; }
            appIn.clear(); SSLEngineResult r = engine.unwrap(netIn, appIn); appIn.flip();
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) throw new SSLException("TLS 握手被关闭");
            if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) { receive(); idle = 0; }
            else if (r.bytesConsumed() == 0 && r.bytesProduced() == 0 && ++idle > 20) throw new SSLException("TLS 握手未前进");
            else idle = 0;
        }
    }
    final InputStream input = new InputStream() {
        @Override public int read() throws IOException { byte[] b = new byte[1]; return read(b, 0, 1) < 0 ? -1 : b[0] & 255; }
        @Override public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            while (!appIn.hasRemaining()) {
                appIn.clear(); SSLEngineResult r;
                try { r = engine.unwrap(netIn, appIn); } catch (SSLException e) { throw e; }
                appIn.flip();
                if (r.getStatus() == SSLEngineResult.Status.CLOSED) return -1;
                if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) { try { receive(); } catch (EOFException e) { return -1; } }
                if (r.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) throw new SSLException("TLS 输入缓冲不足");
                if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) tasks();
                while (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) wrap(EMPTY.duplicate());
            }
            int n = Math.min(len, appIn.remaining()); appIn.get(b, off, n); return n;
        }
    };
    final OutputStream output = new OutputStream() {
        @Override public void write(int b) throws IOException { write(new byte[]{(byte)b}); }
        @Override public void write(byte[] b, int off, int len) throws IOException {
            ByteBuffer src = ByteBuffer.wrap(b, off, len);
            while (src.hasRemaining()) {
                SSLEngineResult r = wrap(src);
                if (r.getStatus() == SSLEngineResult.Status.CLOSED) throw new SSLException("TLS 输出已关闭");
                if (r.bytesConsumed() == 0 && r.bytesProduced() == 0) throw new SSLException("TLS 输出未前进");
            }
        }
    };
    @Override public void close() throws IOException { engine.closeOutbound(); socket.close(); }
}
