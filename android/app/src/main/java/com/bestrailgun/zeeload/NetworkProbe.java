package com.bestrailgun.zeeload;

import java.util.*;
import java.util.regex.*;

final class NetworkProbe {
    static final class Client {
        final String ip, iface, mac;
        Client(String i, String f, String m) { ip = i; iface = f; mac = m; }
        @Override public String toString() { return ip + "  ·  " + iface + (mac.isEmpty() ? "" : "\n" + mac); }
    }
    static List<Client> clients() throws Exception {
        if (!RootShell.exec("id -u").equals("0")) throw new IllegalStateException("未取得 Root 权限");
        State.rootGranted = true;
        String neighbours = RootShell.exec("ip -4 neigh show");
        List<Client> result = new ArrayList<>();
        Pattern p = Pattern.compile("^(\\S+)\\s+dev\\s+(\\S+)(?:.*?lladdr\\s+([0-9a-fA-F:]{17}))?", Pattern.MULTILINE);
        Matcher m = p.matcher(neighbours);
        while (m.find()) {
            if (!privateIp(m.group(1))) continue;
            String mac = "";
            String line = neighbours.substring(m.start(), neighbours.indexOf('\n', m.start()) < 0 ? neighbours.length() : neighbours.indexOf('\n', m.start()));
            Matcher mm = Pattern.compile("lladdr\\s+([0-9a-fA-F:]{17})").matcher(line);
            if (mm.find()) mac = mm.group(1);
            if (!line.contains("FAILED") && !line.contains("INCOMPLETE")) result.add(new Client(m.group(1), m.group(2), mac));
        }
        return result;
    }
    static Client validate(String ip, String iface) throws Exception {
        if (!privateIp(ip)) throw new IllegalArgumentException("请输入车机的局域网 IPv4 地址");
        if (!iface.matches("[a-zA-Z0-9_.-]{1,15}") || iface.equals("lo")) throw new IllegalArgumentException("热点接口名称无效");
        String addresses = RootShell.exec("ip -o -4 addr show dev " + RootShell.quote(iface));
        Matcher m = Pattern.compile("inet\\s+([0-9.]+)/(\\d+)").matcher(addresses);
        long car = number(ip); boolean sameSubnet = false;
        while (m.find()) {
            int bits = Integer.parseInt(m.group(2)); if (bits < 1 || bits > 30) continue;
            long local = number(m.group(1)), mask = (0xffffffffL << (32 - bits)) & 0xffffffffL;
            long network = local & mask, broadcast = network | (~mask & 0xffffffffL);
            if ((car & mask) == network && car != local && car != network && car != broadcast) sameSubnet = true;
        }
        if (!sameSubnet) throw new IllegalArgumentException("车机 IP 与所选接口不在同一网段，请检查热点连接");
        for (Client c : clients()) if (c.ip.equals(ip) && c.iface.equals(iface)) return c;
        // IPv6 filtering needs the peer's MAC. Never silently allow IPv6 to bypass the proxy.
        throw new IllegalArgumentException("尚未发现车机的 MAC 地址，请保持车机连接热点、打开商店后重新检测");
    }
    static boolean privateIp(String s) {
        if (s == null || !s.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) return false;
        String[] o = s.split("\\."); int[] v = new int[4];
        for (int i = 0; i < 4; i++) { v[i] = Integer.parseInt(o[i]); if (v[i] > 255 || (o[i].length() > 1 && o[i].startsWith("0"))) return false; }
        return v[0] == 10 || (v[0] == 172 && v[1] >= 16 && v[1] <= 31) || (v[0] == 192 && v[1] == 168);
    }
    static long number(String ip) { long v = 0; for (String s : ip.split("\\.")) v = (v << 8) | Integer.parseInt(s); return v; }
    private NetworkProbe() { }
}
