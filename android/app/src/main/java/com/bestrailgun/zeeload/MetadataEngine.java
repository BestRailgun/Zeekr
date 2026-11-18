package com.bestrailgun.zeeload;

import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.json.*;

/** Port of addons/zeekr_log.py, with downloads gated by exact host + path. */
final class MetadataEngine {
    final ApkInfo apk; private final String target;
    private final Map<String, Long> armed = new ConcurrentHashMap<>();
    MetadataEngine(ApkInfo a, String pkg) { apk = a; target = pkg; }
    static boolean allowedHost(String host) { return host != null && (host.equalsIgnoreCase("zeekrlife.com") || host.toLowerCase(Locale.US).endsWith(".zeekrlife.com")); }
    static String urlKey(String url) {
        try {
            URI u = new URI(url);
            if (!"https".equalsIgnoreCase(u.getScheme()) || (u.getPort() != -1 && u.getPort() != 443) || !allowedHost(u.getHost())) return "";
            return u.getHost().toLowerCase(Locale.US) + (u.getRawPath().isEmpty() ? "/" : u.getRawPath());
        } catch (Exception e) { return ""; }
    }
    boolean replacementAllowed(String url) {
        String key = urlKey(url); Long time = armed.get(key);
        return time != null && System.nanoTime() - time < 1800_000_000_000L;
    }
    String rewrite(String text) {
        try {
            JSONObject root = new JSONObject(text), data = root.optJSONObject("data");
            if (data == null) return text;
            JSONArray list = data.optJSONArray("list");
            if (data.has("apkPackageName")) list = new JSONArray().put(data);
            if (list == null) return text;
            int changed = 0;
            for (int i = 0; i < list.length(); i++) {
                JSONObject row = list.optJSONObject(i);
                if (row == null || !row.has("apkPackageName")) continue;
                if (!target.equalsIgnoreCase("ALL") && !target.equals("*") && !target.equals(row.optString("apkPackageName"))) continue;
                String key = urlKey(row.optString("apkUrl"));
                if (key.isEmpty()) continue; // Do not advertise an update whose URL cannot be served.
                long version = 1_800_000_000L + Long.parseLong(apk.sha256.substring(0, 7), 16) % 300_000_000L;
                row.put("apkVersion", version).put("apkVersionName", "9.9." + (version % 1000))
                    .put("sha256", apk.sha256).put("apkMd5", apk.md5)
                    .put("apkSize", Math.round(apk.size * 100.0 / 1048576) / 100.0).put("apkSign", "sign");
                armed.put(key, System.nanoTime()); changed++;
            }
            if (changed == 0) return text;
            State.injections.addAndGet(changed);
            State.status("更新信息已就绪", "请在车机当前应用详情页点击更新；已处理 " + changed + " 条信息");
            return root.toString();
        } catch (Exception ignored) { return text; }
    }
}
