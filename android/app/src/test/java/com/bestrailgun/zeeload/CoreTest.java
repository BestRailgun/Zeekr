package com.bestrailgun.zeeload;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

public class CoreTest {
    @Test public void rangesAreExactAndBounded() {
        assertEquals(100, ByteRange.parse(null, 100).length());
        ByteRange r = ByteRange.parse("bytes=15-29", 100); assertEquals(15, r.start); assertEquals(15, r.length()); assertTrue(r.partial);
        assertEquals(10, ByteRange.parse("bytes=-10", 100).length());
        assertEquals(1, ByteRange.parse("bytes=99-", 100).length());
        assertEquals(100, ByteRange.parse("bytes=-999", 100).length());
        assertEquals(20, ByteRange.parse("bytes=80-999", 100).length());
        for (String bad : new String[]{"bytes=100-", "bytes=20-10", "bytes=-0", "bytes=0-0,2-2", "bytes=999999999999999999999999999-"}) {
            try { ByteRange.parse(bad, 100); fail(bad); } catch (IllegalArgumentException expected) { }
        }
    }
    @Test public void chunkedRequestsAndBoundaryConflicts() throws Exception {
        String raw = "POST /app/signature HTTP/1.1\r\nHost: snc-api-gw.zeekrlife.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        HttpCodec.Request req = HttpCodec.read(new ByteArrayInputStream(raw.getBytes(StandardCharsets.US_ASCII)), new ByteArrayOutputStream());
        assertEquals("test", new String(req.body, StandardCharsets.US_ASCII));
        raw = raw.replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked\r\nContent-Length: 4");
        try { HttpCodec.read(new ByteArrayInputStream(raw.getBytes(StandardCharsets.US_ASCII)), new ByteArrayOutputStream()); fail(); } catch (IOException expected) { }
    }
    @Test public void metadataArmsOnlyExactHttpsOriginAndPath() throws Exception {
        File apkFile = File.createTempFile("selected", ".apk");
        try {
            try (OutputStream out = new FileOutputStream(apkFile)) { out.write(new byte[2048]); }
            String sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            MetadataEngine e = new MetadataEngine(new ApkInfo(apkFile, "a.apk", "org.example.test", "1", sha, "0123456789abcdef0123456789abcdef"), "ALL");
            String url = "https://snc-download-cdn.zeekrlife.com/path/app.apk?signature=original";
            assertFalse(e.replacementAllowed(url));
            String src = "{\"data\":{\"apkPackageName\":\"store.original\",\"apkUrl\":\"" + url + "\",\"apkVersion\":1}}";
            JSONObject result = new JSONObject(e.rewrite(src)).getJSONObject("data");
            assertEquals(sha, result.getString("sha256")); assertTrue(result.getLong("apkVersion") > 1800000000L);
            assertEquals("store.original", result.getString("apkPackageName"));
            assertTrue(e.replacementAllowed(url)); assertTrue(e.replacementAllowed(url.replace("signature=original", "signature=new")));
            assertFalse(e.replacementAllowed(url.replace("/path/", "/other/")));
            assertFalse(e.replacementAllowed(url.replace("snc-download-cdn", "unrelated")));
            assertFalse(MetadataEngine.allowedHost("zeekrlife.com.evil.test")); assertFalse(MetadataEngine.allowedHost("evilzeekrlife.com"));
        } finally { apkFile.delete(); }
    }
    @Test public void rejectPublicAndAmbiguousClientAddresses() {
        for (String s : new String[]{"192.168.43.2", "10.1.2.3", "172.16.4.3", "172.31.255.254"}) assertTrue(s, NetworkProbe.privateIp(s));
        for (String s : new String[]{"127.0.0.1", "8.8.8.8", "172.32.0.1", "192.168.1.300", "192.168.01.2", "10.0.0.2;id"}) assertFalse(s, NetworkProbe.privateIp(s));
    }
    @Test public void shellQuotePreservesLiteralInput() throws Exception {
        String value = "a' $(printf BAD) `printf BAD` ; unicode中文";
        Process process = new ProcessBuilder("sh", "-c", "printf '%s' " + RootShell.quote(value)).start();
        ByteArrayOutputStream b = new ByteArrayOutputStream(); byte[] buffer = new byte[1024]; int n;
        while ((n = process.getInputStream().read(buffer)) != -1) b.write(buffer, 0, n);
        assertEquals(0, process.waitFor()); assertEquals(value, b.toString("UTF-8"));
    }
}
