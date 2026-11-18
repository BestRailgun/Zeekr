package com.bestrailgun.zeeload;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.database.Cursor;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.zip.ZipFile;

final class ApkInfo {
    final File file;
    final String name, packageName, version, sha256, md5;
    final long size;
    ApkInfo(File f, String n, String p, String v, String sha, String md) {
        file = f; name = n; packageName = p; version = v; sha256 = sha; md5 = md; size = f.length();
    }
    static ApkInfo importFile(Context c, Uri uri) throws Exception {
        String name = "选择的安装包.apk";
        try (Cursor cur = c.getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cur != null && cur.moveToFirst()) name = cur.getString(0);
        }
        File staged = new File(c.getFilesDir(), "importing.apk");
        try {
            try (InputStream in = c.getContentResolver().openInputStream(uri); OutputStream out = new FileOutputStream(staged)) {
                if (in == null) throw new IOException("无法读取所选文件");
                byte[] buf = new byte[128 * 1024]; int n;
                while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            }
            // SAF URIs do not necessarily have an .apk suffix. Inspect content, not the URI string.
            try (ZipFile zip = new ZipFile(staged)) {
                if (zip.getEntry("AndroidManifest.xml") == null) throw new IOException("文件不是有效的 APK；请解压 ZIP 后选择其中的 APK");
            }
            PackageInfo pkg = c.getPackageManager().getPackageArchiveInfo(staged.getPath(), 0);
            if (pkg == null) throw new IOException("无法解析 APK 清单；不支持 APKM、XAPK 或拆分安装包");
            String[] hashes = hash(staged);
            File target = new File(c.getFilesDir(), "selected.apk");
            Files.move(staged.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
            ApkInfo info = new ApkInfo(target, name, pkg.packageName, pkg.versionName, hashes[0], hashes[1]);
            c.getSharedPreferences("apk", 0).edit().putString("name", name).putString("package", pkg.packageName)
                .putString("version", pkg.versionName).putString("sha", hashes[0]).putString("md5", hashes[1]).commit();
            return info;
        } finally { if (staged.exists()) staged.delete(); }
    }
    static ApkInfo restore(Context c) {
        File f = new File(c.getFilesDir(), "selected.apk"); SharedPreferences p = c.getSharedPreferences("apk", 0);
        if (!f.isFile() || !p.contains("sha")) return null;
        return new ApkInfo(f, p.getString("name", "安装包.apk"), p.getString("package", ""), p.getString("version", ""), p.getString("sha", ""), p.getString("md5", ""));
    }
    static String[] hash(File f) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256"), md = MessageDigest.getInstance("MD5");
        try (InputStream in = new FileInputStream(f)) {
            byte[] b = new byte[128 * 1024]; int n;
            while ((n = in.read(b)) != -1) { sha.update(b, 0, n); md.update(b, 0, n); }
        }
        return new String[]{hex(sha.digest()), hex(md.digest())};
    }
    private static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format(Locale.US, "%02x", x & 255)); return s.toString(); }
}
