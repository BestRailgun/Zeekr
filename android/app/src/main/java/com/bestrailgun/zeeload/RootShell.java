package com.bestrailgun.zeeload;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

final class RootShell {
    static String exec(String command) throws Exception {
        Process p;
        try { p = new ProcessBuilder("su", "-c", command).redirectErrorStream(true).start(); }
        catch (IOException e) { throw new IOException("找不到 su，请检查手机 Root 管理器", e); }
        FutureTask<String> read = new FutureTask<>(() -> {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream in = p.getInputStream()) {
                byte[] b = new byte[4096]; int n;
                while ((n = in.read(b)) != -1) { if (out.size() < 1024 * 1024) out.write(b, 0, n); }
            }
            return out.toString("UTF-8").trim();
        });
        Thread reader = new Thread(read, "root-output"); reader.setDaemon(true); reader.start();
        try {
            if (!p.waitFor(45, TimeUnit.SECONDS)) throw new IOException("Root 命令超时，请检查授权弹窗");
            String output = read.get(3, TimeUnit.SECONDS);
            if (p.exitValue() != 0) throw new IOException("Root 命令失败：" + output);
            return output;
        } finally { p.destroy(); }
    }
    static String quote(String s) { return "'" + s.replace("'", "'\"'\"'") + "'"; }
    static void write(File file, String text) throws IOException {
        try (OutputStream out = new FileOutputStream(file)) { out.write(text.getBytes(StandardCharsets.UTF_8)); }
    }
    private RootShell() { }
}
