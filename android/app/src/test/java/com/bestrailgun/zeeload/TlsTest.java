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
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Future<?> complete = worker.submit(() -> {
                try (Socket s = server.accept()) {
                    s.setSoTimeout(10000); ClientHello hello = ClientHello.read(s.getInputStream()); assertEquals("snc-api-gw.zeekrlife.com", hello.host);
                    SSLEngine engine = certificates.engine(hello.host); engine.setEnabledProtocols(new String[]{protocol});
                    try (TlsChannel tls = new TlsChannel(s, engine, hello.raw)) {
                        assertEquals(42, tls.input.read()); tls.output.write(payload);
                    }
                } catch (Exception e) { throw new RuntimeException(e); }
            });
            SSLContext client = SSLContext.getInstance("TLS");
            // Test-only trust manager: production upstream uses OkHttp's normal platform validation.
            client.init(null, new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) { }
                public void checkServerTrusted(X509Certificate[] c, String a) { }
            }}, new SecureRandom());
            try (SSLSocket socket = (SSLSocket)client.getSocketFactory().createSocket(InetAddress.getLoopbackAddress(), server.getLocalPort())) {
                socket.setSoTimeout(10000); socket.setEnabledProtocols(new String[]{protocol});
                SSLParameters p = socket.getSSLParameters(); p.setServerNames(Collections.singletonList(new SNIHostName("snc-api-gw.zeekrlife.com"))); socket.setSSLParameters(p);
                socket.startHandshake(); socket.getOutputStream().write(42); socket.getOutputStream().flush();
                assertArrayEquals(payload, ClientHello.exact(socket.getInputStream(), payload.length));
            }
            complete.get(15, TimeUnit.SECONDS);
        } finally { worker.shutdownNow(); }
    }
}
