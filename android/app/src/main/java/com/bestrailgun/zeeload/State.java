package com.bestrailgun.zeeload;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/** In-process status; never infer installation success from network transfer. */
final class State {
    static volatile boolean active, busy, rootGranted;
    static volatile String status = "准备就绪", detail = "选择安装包，开启手机热点并连接车机";
    static volatile ApkInfo apk;
    static final AtomicLong connections = new AtomicLong(), injections = new AtomicLong(), bytes = new AtomicLong();
    private static final ArrayDeque<String> lines = new ArrayDeque<>();

    static synchronized void log(String message) {
        message = message.replaceAll("(https?://[^\\s?#]+)[?#][^\\s]*", "$1?[redacted]");
        String stamp = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        lines.addLast(stamp + "  " + message);
        while (lines.size() > 180) lines.removeFirst();
    }
    static synchronized String logs() { return String.join("\n", lines); }
    static void status(String title, String subtitle) { status = title; detail = subtitle; log(title + " · " + subtitle); }
    private State() { }
}
