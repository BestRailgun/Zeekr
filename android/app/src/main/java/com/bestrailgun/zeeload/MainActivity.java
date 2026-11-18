package com.bestrailgun.zeeload;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.*;
import android.provider.Settings;
import android.view.*;
import android.widget.*;
import java.util.*;
import java.util.concurrent.*;

public final class MainActivity extends Activity {
    private static final int ORANGE = Color.rgb(255, 128, 47), WHITE = Color.rgb(243, 244, 248), MUTED = Color.rgb(159, 164, 178), BG = Color.rgb(16, 17, 20), PANEL = Color.rgb(27, 29, 34);
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView titleState, detailState, fileInfo, logView, metrics, badge;
    private EditText ip, iface, target;
    private Switch oldChain;
    private Button choose, discover, start, stop;
    private boolean working, rootGranted;
    private String previousLog = "";
    private final Runnable refresh = new Runnable() { @Override public void run() { render(); handler.postDelayed(this, 800); } };
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if (State.apk == null) State.apk = ApkInfo.restore(this);
        build();
        if (new RootRules(this).pending() && !State.active) State.status("发现未恢复的网络会话", "请先点击恢复网络，再启动新会话");
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 9);
    }
    private void build() {
        LinearLayout frame = column(); frame.setBackgroundColor(BG);
        frame.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) { android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars()); view.setPadding(bars.left, bars.top, bars.right, bars.bottom); }
            else view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(), insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true);
        LinearLayout content = column(); content.setPadding(dp(20), dp(24), dp(20), dp(16)); scroll.addView(content); frame.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        TextView eyebrow = text("ZEELOAD  /  ANDROID", 12, ORANGE); eyebrow.setLetterSpacing(0.14f); content.addView(eyebrow);
        LinearLayout header = row(); TextView name = text("极载", 36, WHITE); name.setTypeface(null, Typeface.BOLD); header.addView(name, new LinearLayout.LayoutParams(0, -2, 1));
        badge = text("ROOT 待检查", 11, ORANGE); badge.setPadding(dp(10), dp(7), dp(10), dp(7)); badge.setBackground(shape(Color.rgb(49, 34, 24), 20)); header.addView(badge); content.addView(header);
        addText(content, "让手机成为车机的安装助手", 15, MUTED, 6);
        LinearLayout status = card(content, 20); titleState = text(State.status, 19, WHITE); titleState.setTypeface(null, Typeface.BOLD); status.addView(titleState);
        detailState = text(State.detail, 13, MUTED); marginAdd(status, detailState, 8);
        metrics = text("连接 0    更新信息 0    已发送 0 MB", 11, ORANGE); marginAdd(status, metrics, 14);

        LinearLayout file = card(content, 12); section(file, "01", "选择安装包");
        fileInfo = text("选择手机中的 APK 文件\n自动读取包名、版本和校验值", 13, MUTED); marginAdd(file, fileInfo, 12);
        choose = button("选择 APK 文件", false); marginAdd(file, choose, 14);
        choose.setOnClickListener(v -> { Intent open = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"); startActivityForResult(open, 1); });

        LinearLayout network = card(content, 12); section(network, "02", "连接你的车机");
        addText(network, "开启手机热点，让车机连接，再检测并选择车机。多个设备时，请核对车机 IP。", 13, MUTED, 12);
        LinearLayout actions = row(); Button hotspot = button("热点设置", false); discover = button("检测连接", false);
        LinearLayout.LayoutParams left = new LinearLayout.LayoutParams(0, dp(48), 1); left.setMargins(0, 0, dp(8), 0); actions.addView(hotspot, left); actions.addView(discover, new LinearLayout.LayoutParams(0, dp(48), 1)); marginAdd(network, actions, 14);
        hotspot.setOnClickListener(v -> { try { startActivity(new Intent("android.settings.TETHER_SETTINGS")); } catch (ActivityNotFoundException e) { startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS)); } });
        discover.setOnClickListener(v -> discoverClients());
        SharedPreferences prefs = getSharedPreferences("ui", 0);
        ip = input("车机 IP，例如 192.168.43.20", prefs.getString("ip", "")); marginAdd(network, ip, 12);
        iface = input("热点接口，例如 ap0 / wlan0", prefs.getString("iface", "")); marginAdd(network, iface, 8);

        LinearLayout advanced = card(content, 12);
        TextView toggle = text("高级选项  ＋", 14, MUTED); advanced.addView(toggle);
        LinearLayout fields = column(); fields.setVisibility(View.GONE); advanced.addView(fields);
        toggle.setOnClickListener(v -> { boolean open = fields.getVisibility() != View.VISIBLE; fields.setVisibility(open ? View.VISIBLE : View.GONE); toggle.setText(open ? "高级选项  －" : "高级选项  ＋"); });
        addText(fields, "注入目标：ALL 表示匹配商店全部应用；也可填写单个商店应用的包名。", 12, MUTED, 14);
        target = input("ALL", prefs.getString("target", "ALL")); marginAdd(fields, target, 8);
        oldChain = new Switch(this); oldChain.setText("旧版证书信任链兼容"); oldChain.setTextColor(WHITE); oldChain.setTextSize(13); oldChain.setChecked(prefs.getBoolean("oldChain", false)); marginAdd(fields, oldChain, 14);
        addText(fields, "仅在默认证书握手失败时尝试。车机已修复相关机制时，本工具无法完成侧载。", 12, MUTED, 8);

        LinearLayout instructions = card(content, 12); section(instructions, "03", "启动后，在车机操作");
        addText(instructions, "打开应用商店 → 进入应用详情页 → 点击更新\n下载完成后，在车机确认安装结果。", 13, MUTED, 12);
        TextView logsToggle = text("运行日志  ＋", 13, ORANGE); marginAdd(content, logsToggle, 20);
        logView = text("日志将在这里显示", 11, MUTED); logView.setTypeface(Typeface.MONOSPACE); logView.setTextIsSelectable(true); logView.setVisibility(View.GONE); marginAdd(content, logView, 10);
        logsToggle.setOnClickListener(v -> { boolean show = logView.getVisibility() != View.VISIBLE; logView.setVisibility(show ? View.VISIBLE : View.GONE); logsToggle.setText(show ? "运行日志  －" : "运行日志  ＋"); });
        TextView copy = text("复制诊断日志", 12, MUTED); copy.setPadding(0, dp(12), 0, dp(12)); content.addView(copy);
        copy.setOnClickListener(v -> { getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("ZEEload", "ZEEload " + BuildConfig.VERSION_NAME + " · Android " + Build.VERSION.RELEASE + "\n" + State.logs())); Toast.makeText(this, "诊断日志已复制", Toast.LENGTH_SHORT).show(); });
        addText(content, "适用于自有车辆。日志保留在本次应用进程中。", 11, MUTED, 4);

        LinearLayout footer = column(); footer.setPadding(dp(20), dp(12), dp(20), dp(14)); footer.setBackgroundColor(BG);
        start = button("启动安装服务", true); footer.addView(start, new LinearLayout.LayoutParams(-1, dp(54))); start.setOnClickListener(v -> startProxy());
        stop = button("停止并恢复网络", false); marginAdd(footer, stop, 8); stop.setOnClickListener(v -> stopProxy());
        frame.addView(footer); setContentView(frame);
    }
    private void discoverClients() {
        task("正在检查 Root 与连接设备…", () -> {
            List<NetworkProbe.Client> found = NetworkProbe.clients(); rootGranted = true;
            onUi(() -> {
                if (found.isEmpty()) { message("未发现设备", "请确认车机已连接手机热点，并在车机打开商店后再检测。也可手动填写车机 IP 和热点接口。"); return; }
                String[] choices = new String[found.size()]; for (int i = 0; i < choices.length; i++) choices[i] = found.get(i).toString();
                new AlertDialog.Builder(this).setTitle("选择你的车机").setItems(choices, (d, index) -> { ip.setText(found.get(index).ip); iface.setText(found.get(index).iface); save(); }).setNegativeButton("取消", null).show();
            });
        });
    }
    private void startProxy() {
        if (State.apk == null) { message("请先选择 APK", "选择需要安装到车机的完整 APK 文件。"); return; }
        if (ip.getText().toString().trim().isEmpty() || iface.getText().toString().trim().isEmpty()) { discoverClients(); return; }
        save();
        Intent args = new Intent(this, ProxyService.class).putExtra("ip", ip.getText().toString().trim()).putExtra("iface", iface.getText().toString().trim())
            .putExtra("target", target.getText().toString().trim()).putExtra("oldChain", oldChain.isChecked());
        try { startForegroundService(args); } catch (RuntimeException e) { message("无法启动服务", e.getMessage()); }
    }
    private void stopProxy() {
        if (State.active) { startService(new Intent(this, ProxyService.class).setAction(ProxyService.STOP)); return; }
        task("正在恢复网络…", () -> { new RootRules(this).restore(); State.status("网络已恢复", "本工具的热点转发规则已清理"); });
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 1 && result == RESULT_OK && data != null && data.getData() != null) {
            Uri uri = data.getData();
            task("正在读取和校验 APK…", () -> { if (State.active) throw new IllegalStateException("请先停止安装服务"); State.apk = ApkInfo.importFile(this, uri); State.log("已选择 " + State.apk.packageName + " · " + State.apk.size + " 字节"); });
        }
    }
    private interface Work { void run() throws Exception; }
    private void task(String text, Work work) {
        if (working || State.active) return;
        working = true; State.log(text); render();
        worker.execute(() -> { try { work.run(); } catch (Exception e) { State.log("操作失败：" + e.getMessage()); onUi(() -> message("操作未完成", e.getMessage())); } finally { working = false; onUi(this::render); } });
    }
    private void render() {
        if (titleState == null) return;
        titleState.setText(working ? "正在处理…" : State.status); detailState.setText(State.detail);
        badge.setText(rootGranted || State.rootGranted ? "ROOT 已授权" : "ROOT 待检查");
        ApkInfo a = State.apk; fileInfo.setText(a == null ? "选择手机中的 APK 文件\n自动读取包名、版本和校验值" : a.name + "\n" + a.packageName + " · " + Objects.toString(a.version, "") + "\n" + String.format(Locale.US, "%.1f MB  ·  SHA256 %s…", a.size / 1048576.0, a.sha256.substring(0, 12)));
        metrics.setText(String.format(Locale.US, "连接 %d    更新信息 %d    已发送 %.1f MB", State.connections.get(), State.injections.get(), State.bytes.get() / 1048576.0));
        String logs = State.logs(); if (!logs.equals(previousLog)) { logView.setText(logs); previousLog = logs; }
        boolean edit = !State.active && !State.busy && !working;
        for (View v : new View[]{choose, discover, ip, iface, target, oldChain}) { v.setEnabled(edit); v.setAlpha(edit ? 1f : 0.5f); }
        start.setEnabled(edit && a != null); start.setAlpha(start.isEnabled() ? 1 : 0.45f);
        stop.setEnabled(!working); stop.setText(State.active ? "停止并恢复网络" : "恢复网络");
    }
    private void save() { getSharedPreferences("ui", 0).edit().putString("ip", ip.getText().toString().trim()).putString("iface", iface.getText().toString().trim()).putString("target", target.getText().toString().trim()).putBoolean("oldChain", oldChain.isChecked()).apply(); }
    private void onUi(Runnable r) { runOnUiThread(() -> { if (!isDestroyed()) r.run(); }); }
    private void message(String title, String text) { new AlertDialog.Builder(this).setTitle(title).setMessage(text).setPositiveButton("知道了", null).show(); }
    @Override protected void onResume() { super.onResume(); handler.post(refresh); }
    @Override protected void onPause() { handler.removeCallbacks(refresh); save(); super.onPause(); }
    @Override protected void onDestroy() { worker.shutdown(); super.onDestroy(); }
    private int dp(int n) { return (int)(n * getResources().getDisplayMetrics().density + 0.5f); }
    private LinearLayout column() { LinearLayout v = new LinearLayout(this); v.setOrientation(LinearLayout.VERTICAL); return v; }
    private LinearLayout row() { LinearLayout v = new LinearLayout(this); v.setOrientation(LinearLayout.HORIZONTAL); v.setGravity(Gravity.CENTER_VERTICAL); return v; }
    private TextView text(String s, int size, int color) { TextView v = new TextView(this); v.setText(s); v.setTextSize(size); v.setTextColor(color); v.setLineSpacing(dp(3), 1f); return v; }
    private GradientDrawable shape(int color, int radius) { GradientDrawable d = new GradientDrawable(); d.setColor(color); d.setCornerRadius(dp(radius)); return d; }
    private LinearLayout card(LinearLayout parent, int gap) { LinearLayout c = column(); c.setPadding(dp(18), dp(18), dp(18), dp(18)); c.setBackground(shape(PANEL, 18)); marginAdd(parent, c, gap); return c; }
    private void marginAdd(LinearLayout parent, View view, int top) { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2); p.topMargin = dp(top); parent.addView(view, p); }
    private void addText(LinearLayout p, String s, int size, int color, int gap) { marginAdd(p, text(s, size, color), gap); }
    private void section(LinearLayout parent, String number, String title) { LinearLayout r = row(); TextView no = text(number + "  ", 14, ORANGE); no.setTypeface(null, Typeface.BOLD); r.addView(no); TextView t = text(title, 16, WHITE); t.setTypeface(null, Typeface.BOLD); r.addView(t); parent.addView(r); }
    private Button button(String label, boolean primary) { Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setTextColor(primary ? BG : WHITE); b.setTextSize(14); b.setMinHeight(dp(48)); b.setPadding(dp(12), dp(8), dp(12), dp(8)); b.setBackground(shape(primary ? ORANGE : Color.rgb(43, 46, 54), 12)); return b; }
    private EditText input(String hint, String value) { EditText e = new EditText(this); e.setSingleLine(true); e.setTextColor(WHITE); e.setHintTextColor(MUTED); e.setTextSize(13); e.setPadding(dp(12), dp(12), dp(12), dp(12)); e.setBackground(shape(Color.rgb(38, 41, 48), 10)); e.setHint(hint); e.setText(value); e.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS); return e; }
}
