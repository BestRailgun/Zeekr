package com.bestrailgun.zeeload;

import org.junit.Test;
import static org.junit.Assert.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;

public class TlsTest {
    @Test public void clientHelloReplayAndLargeTlsBody() throws Exception { roundTrip(false, "TLSv1.2"); roundTrip(false, "TLSv1.3"); }
    @Test public void alternateCertificateChainWorks() throws Exception { roundTrip(true, "TLSv1.2"); }
    private void roundTrip(boolean old, String protocol) throws Exception {
        Certificates certificates = new Certificates(new FileInputStream("src/main/assets/emudhra-chain.pem"), old);
        byte[] payload = new byte[700000]; new Random(3).nextBytes(payload);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        PipedInputStream serverIn = new PipedInputStream(262144), clientIn = new PipedInputStream(262144);
        Socket serverSocket = memorySocket(serverIn, new PipedOutputStream(clientIn));
        Socket clientSocket = memorySocket(clientIn, new PipedOutputStream(serverIn));
        try {
            Future<?> complete = worker.submit(() -> {
                try (Socket s = serverSocket) {
                    ClientHello hello = ClientHello.read(s.getInputStream()); assertEquals("snc-api-gw.zeekrlife.com", hello.host);
                    SSLEngine engine = certificates.engine(hello.host); engine.setEnabledProtocols(new String[]{protocol});
                    try (TlsChannel tls = new TlsChannel(s, engine, hello.raw)) {
                        assertEquals(42, tls.input.read()); tls.output.write(payload);
                    }
                } catch (Exception e) { e.printStackTrace(); throw new RuntimeException(e); }
            });
            SSLContext client = SSLContext.getInstance("TLS");
            // Test-only trust manager: production upstream uses OkHttp's normal platform validation.
            client.init(null, new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) { }
                public void checkServerTrusted(X509Certificate[] c, String a) { }
            }}, new SecureRandom());
            SSLEngine clientEngine = client.createSSLEngine("snc-api-gw.zeekrlife.com", 443); clientEngine.setUseClientMode(true); clientEngine.setEnabledProtocols(new String[]{protocol});
            SSLParameters p = clientEngine.getSSLParameters(); p.setServerNames(Collections.singletonList(new SNIHostName("snc-api-gw.zeekrlife.com"))); clientEngine.setSSLParameters(p);
            try (TlsChannel socket = new TlsChannel(clientSocket, clientEngine, new byte[0])) {
                socket.output.write(42);
                assertArrayEquals(payload, ClientHello.exact(socket.input, payload.length));
            }
            complete.get(15, TimeUnit.SECONDS);
        } finally { serverSocket.close(); clientSocket.close(); worker.shutdownNow(); }
    }
    private Socket memorySocket(InputStream in, OutputStream out) {
        return new Socket() {
            @Override public InputStream getInputStream() { return in; }
            @Override public OutputStream getOutputStream() { return out; }
            @Override public void close() throws IOException { in.close(); out.close(); }
        };
    }
}
