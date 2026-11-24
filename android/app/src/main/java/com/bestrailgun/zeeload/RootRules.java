package com.bestrailgun.zeeload;

import android.content.Context;
import android.os.Process;
import java.io.*;
import java.util.UUID;

/** Dedicated chains only. A root watchdog rolls back if the app process disappears. */
final class RootRules {
    static final int PORT = 18443;
    private final File cleanup, marker, watchdog;
    RootRules(Context context) {
        cleanup = new File(context.getFilesDir(), "network-cleanup.sh");
        marker = new File(context.getFilesDir(), "network-session");
        watchdog = new File(context.getFilesDir(), "network-watchdog.sh");
    }
    boolean pending() { return marker.exists(); }
    synchronized void restore() throws Exception {
        if (!marker.exists()) return;
        if (!cleanup.isFile()) throw new IOException("网络恢复脚本丢失，请在日志中检查专用 ZLAD 规则");
        RootShell.exec("/system/bin/sh " + q(cleanup));
        if (marker.exists()) throw new IOException("网络恢复尚未完成，请重试");
    }
    synchronized void install(NetworkProbe.Client c) throws Exception {
        restore();
        if (!c.mac.matches("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")) throw new IOException("无法确定车机 MAC 地址");
        RootShell.exec("iptables -w 5 -t nat -L -n >/dev/null && iptables -w 5 -L -n >/dev/null && ip6tables -w 5 -L -n >/dev/null && command -v nohup >/dev/null");
        String oldOffload = RootShell.exec("settings get global tether_offload_disabled");
        if (!oldOffload.matches("null|[0-9]+")) throw new IOException("无法读取热点加速设置");
        String iface = RootShell.quote(c.iface), ip = RootShell.quote(c.ip), mac = RootShell.quote(c.mac);
        String natJump = "-i " + iface + " -s " + ip + " -p tcp --dport 443 -j ZLAD_N";
        String inputJump = "-i " + iface + " -s " + ip + " -p tcp --dport " + PORT + " -j ZLAD_I";
        String forwardJump = "-i " + iface + " -s " + ip + " -j ZLAD_F";
        String v6Jump = "-i " + iface + " -m mac --mac-source " + mac + " -j ZLAD6_F";
        String token = UUID.randomUUID().toString();
        String restoreSetting = oldOffload.equals("null") ? "settings delete global tether_offload_disabled" : "settings put global tether_offload_disabled " + oldOffload;
        String rollback = "#!/system/bin/sh\nset -e\n" +
            "[ -f " + q(marker) + " ] || exit 0\n" +
            "iptables -w 5 -L -n >/dev/null\nip6tables -w 5 -L -n >/dev/null\n" +
            remove("iptables -w 5 -t nat", "PREROUTING", natJump, "ZLAD_N") +
            remove("iptables -w 5", "INPUT", inputJump, "ZLAD_I") +
            remove("iptables -w 5", "FORWARD", forwardJump, "ZLAD_F") +
            remove("ip6tables -w 5", "FORWARD", v6Jump, "ZLAD6_F") +
            "if [ \"$(settings get global tether_offload_disabled)\" = 1 ]; then " + restoreSetting + "; fi\n" +
            "rm -f " + q(marker) + "\n";
        RootShell.write(cleanup, rollback);
        RootShell.write(marker, token + "\n");
        String check = "[ \"$(cat " + q(marker) + " 2>/dev/null)\" = " + RootShell.quote(token) + " ]";
        String ownerStart = RootShell.exec("cat /proc/" + Process.myPid() + "/stat");
        String startTime = ownerStart.substring(ownerStart.lastIndexOf(')') + 2).split(" ")[19];
        RootShell.write(watchdog, "#!/system/bin/sh\n" +
            "while " + check + " && [ \"$(cat /proc/" + Process.myPid() + "/stat 2>/dev/null | sed 's/.*) //' | awk '{print $20}')\" = " + RootShell.quote(startTime) + " ]; do sleep 3; done\n" +
            "if " + check + "; then /system/bin/sh " + q(cleanup) + "; fi\n");
        try {
            RootShell.exec("nohup /system/bin/sh " + q(watchdog) + " >/dev/null 2>&1 </dev/null &");
            RootShell.exec("set -e\n" +
                "settings put global tether_offload_disabled 1\n" +
                "iptables -w 5 -t nat -N ZLAD_N\n" + redirectCommand() + "\n" +
                "iptables -w 5 -N ZLAD_I\niptables -w 5 -A ZLAD_I -j ACCEPT\n" +
                "iptables -w 5 -N ZLAD_F\niptables -w 5 -A ZLAD_F -p udp --dport 443 -j REJECT\niptables -w 5 -A ZLAD_F -j RETURN\n" +
                "ip6tables -w 5 -N ZLAD6_F\nip6tables -w 5 -A ZLAD6_F -p tcp --dport 443 -j REJECT --reject-with tcp-reset\nip6tables -w 5 -A ZLAD6_F -p udp --dport 443 -j REJECT\nip6tables -w 5 -A ZLAD6_F -j RETURN\n" +
                "iptables -w 5 -t nat -I PREROUTING 1 " + natJump + "\n" +
                "iptables -w 5 -I INPUT 1 " + inputJump + "\n" +
                "iptables -w 5 -I FORWARD 1 " + forwardJump + "\n" +
                "ip6tables -w 5 -I FORWARD 1 " + v6Jump + "\n");
        } catch (Exception failure) {
            try { restore(); } catch (Exception e) { failure.addSuppressed(e); }
            throw failure;
        }
    }
    static String redirectCommand() {
        // REDIRECT validates its own protocol; a TCP match in the parent chain is insufficient.
        return "iptables -w 5 -t nat -A ZLAD_N -p tcp -j REDIRECT --to-ports " + PORT;
    }
    private static String remove(String binary, String parent, String rule, String chain) {
        return "while " + binary + " -C " + parent + " " + rule + " 2>/dev/null; do " + binary + " -D " + parent + " " + rule + "; done\n" +
            "if " + binary + " -S " + chain + " >/dev/null 2>&1; then ( " + binary + " -F " + chain + " && " + binary + " -X " + chain + " ) || ! " + binary + " -S " + chain + " >/dev/null 2>&1; fi\n";
    }
    private static String q(File f) { return RootShell.quote(f.getAbsolutePath()); }
}
