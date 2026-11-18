package com.bestrailgun.zeeload;

import android.annotation.SuppressLint;
import android.app.*;
import android.content.*;
import android.os.*;
import java.util.concurrent.*;

public final class ProxyService extends Service {
    static final String STOP = "com.bestrailgun.zeeload.STOP";
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private ProxyServer server;
    private RootRules rules;
    private PowerManager.WakeLock wake;
    private volatile boolean stopping, stopRequested;
    private boolean started;
    @Override public void onCreate() {
        super.onCreate(); rules = new RootRules(this);
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("proxy", "极载运行服务", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, ProxyService.class).setAction(STOP), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification notification = new Notification.Builder(this, "proxy").setSmallIcon(com.bestrailgun.zeeload.R.drawable.ic_launcher)
            .setContentTitle("极载 ZEEload").setContentText("车机安装服务运行中 · 点击返回界面")
            .setOngoing(true).setContentIntent(open).addAction(new Notification.Action.Builder(null, "停止并恢复网络", stop).build()).build();
        startForeground(1, notification);
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            stopRequested = true;
            if (!stopping) worker.execute(this::finishSession);
            return START_NOT_STICKY;
        }
        if (started) return START_NOT_STICKY;
        started = true; State.active = true; State.busy = true;
        Intent args = intent == null ? new Intent() : new Intent(intent);
        worker.execute(() -> begin(args));
        return START_NOT_STICKY;
    }
    @SuppressLint("WakelockTimeout")
    private void begin(Intent args) {
        try {
            State.status("正在检查运行环境", "请允许 Root 授权，保持手机热点开启");
            ApkInfo apk = State.apk == null ? ApkInfo.restore(this) : State.apk;
            if (apk == null) throw new IllegalArgumentException("请先选择 APK");
            NetworkProbe.Client car = NetworkProbe.validate(args.getStringExtra("ip"), args.getStringExtra("iface"));
            String target = args.getStringExtra("target");
            if (target == null || !(target.equals("*") || target.equalsIgnoreCase("ALL") || target.matches("[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z0-9_]+)+"))) throw new IllegalArgumentException("注入目标包名无效");
            if (stopRequested) { finishSession(); return; }
            rules.restore();
            State.status("正在初始化内置代理", "正在准备本地证书和热点转发");
            Certificates certificates = new Certificates(this, args.getBooleanExtra("oldChain", false));
            server = new ProxyServer(certificates, new MetadataEngine(apk, target), car.ip); server.start();
            if (stopRequested) { finishSession(); return; }
            rules.install(car);
            wake = getSystemService(PowerManager.class).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "zeeload:transfer"); wake.acquire();
            State.connections.set(0); State.injections.set(0); State.bytes.set(0);
            State.status("等待车机请求", "打开车机应用商店，进入任意应用详情页，再点击更新");
            State.log("已绑定车机 " + car.ip + " · " + car.iface + "；仅处理该设备的连接");
            State.log("若连接数一直为 0：关闭手机热点硬件加速，重开热点并重新检测车机地址");
            State.busy = false;
            if (stopRequested) finishSession();
        } catch (Exception e) {
            State.status("启动失败", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            finishSession();
        }
    }
    private void cleanup() throws Exception {
        // Restore routes before closing the listener; an error keeps the recovery journal.
        Exception failure = null;
        try { rules.restore(); } catch (Exception e) { failure = e; }
        if (server != null) { server.close(); server = null; }
        if (wake != null && wake.isHeld()) wake.release();
        if (failure != null) throw failure;
    }
    private void finishSession() {
        if (stopping) return;
        stopping = true; State.busy = true;
        boolean startupFailure = State.status.equals("启动失败");
        try {
            cleanup();
            if (!startupFailure) State.status("服务已停止", "热点转发规则已恢复，可重新选择 APK");
        } catch (Exception e) { State.status("网络恢复需要重试", "点击恢复网络：" + e.getMessage()); }
        finally { State.active = false; State.busy = false; stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); }
    }
    @Override public void onDestroy() {
        if (!stopping) worker.execute(this::finishSession);
        worker.shutdown(); super.onDestroy();
    }
    @Override public IBinder onBind(Intent intent) { return null; }
}
