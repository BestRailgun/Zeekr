# 极载 ZEEload · Android

安卓原生 GUI，面向已 Root 的安卓手机。将手机作为热点网关，为连接该热点的自有极氪车机处理商店元数据和 APK 下载。

## 手机使用

1. 安装 `ZEELoad-Android-0.1.1.apk`，打开应用。首次允许通知，以便在通知栏停止服务。
2. 点击“选择 APK 文件”，选择需要安装到车机的完整 APK。支持系统文件选择器和文件管理器的内容 URI，不依赖 URI 文件名后缀。不支持 XAPK、APKM、拆分安装包和压缩包内的 APK，请先解压。
3. 点击“热点设置”，开启手机热点，并让车机连接该热点。
4. 点击“检测连接”，在 Magisk / KernelSU / APatch 等 Root 管理器中允许本应用使用 `su`，核对并选择车机 IP。邻居列表可能同时显示手机上游网关，请按车机网络设置核对。
5. 点击“启动安装服务”，在车机应用商店打开一个应用详情页，等待手机显示“更新信息已就绪”，然后在车机点击更新。
6. 在车机确认最终安装结果后，点击“停止并恢复网络”。下载流量和服务状态不代表车机已经安装成功。

首次授予 Root、打开热点、连接车机和车机商店内的操作仍需完成。安装包内已包含 GUI、TLS/HTTP 代理、校验和计算、元数据处理和网络恢复，不需要 Termux、Python、mitmproxy、电脑或外置 ADB 客户端。手机 ADB 权限不能代替应用自身的 `su` 授权。没有向车机建立 ADB 连接，也不需要车机开启 ADB。

## 适用范围与限制

- Android 8.0（API 26）及以上；原生 Java，无 ABI 特定可执行文件，可运行于 ARM64 / ARM32 / x86_64。
- 手机必须具有可用的 `su`、`ip`、`iptables`、`ip6tables` 和 `nohup`。不具备 IPv6 防绕过能力或检测不到车机 MAC 时，启动会明确失败。
- 车机必须通过手机热点联网，且应用商店仍符合仓库原有的信任链与安装机制。手机 Root 并不能保证所有车机版本都可侧载。新版 OTA、根证书吊销、证书固定或商店机制修复可能令该方法失效。
- 本版处理带 SNI 的 HTTPS / HTTP 1.1；不支持 ECH、无 SNI TLS 或必须使用 HTTP/2 的客户端。非 `zeekrlife.com` 域名的 TLS 连接按原始加密数据转发。
- 仅 IPv4 代理，按所选车机 MAC 阻止其 IPv6 HTTPS，并阻止该车机 UDP 443，以便回退到 IPv4 TCP。
- 启动时会临时设置 `tether_offload_disabled=1`，停止时还原原值。部分系统需要重开热点后才生效；厂商 eBPF / 专有热点加速仍可能绕过 iptables。连接数持续为 0 时，应先停止服务，关闭“网络共享硬件加速”、重开热点、重新检测车机，再启动。不自动重启热点或清理系统连接表。
- 默认仅处理 `*.zeekrlife.com`。对于元数据指向其他 CDN 的条目，不发布无法服务的更新，不默认扩大解密范围。
- 新包侧载遵循原项目机制。相同包名、签名冲突和车机桌面过滤等限制仍然存在；并非通用升级器。

## 实现

- `MainActivity`：橙黑原生界面、SAF 选择 APK、设备检测、状态、日志、网络恢复。
- `ProxyService`：前台服务、通知栏停止入口、唤醒锁；退出 Activity 后可继续传输。
- `RootRules`：只创建 `ZLAD_N`、`ZLAD_I`、`ZLAD_F`、`ZLAD6_F` 专用链。转发仅按所选车机接口、IP 和 MAC 生效，不清空系统防火墙。仅该车机的 TCP 443 重定向到 18443；监听器拒绝其他来源。
- 网络修改前保存恢复脚本和会话标记，并启动 Root 看护进程。正常停止、启动失败会执行恢复；应用进程消失时，看护进程尝试恢复。再次打开时发现残留会话会提供恢复入口。Root 管理器行为、系统进程组回收和 SELinux 仍须实机验证；不应在正在传输时卸载应用或清除数据。
- `ClientHello` + `TlsChannel` + `Certificates`：SNI 解析、SSLEngine 解密、按域名签发临时证书。无隐藏 API、无外置二进制。上游使用正常证书校验，不设置宽松 TrustManager。
- `MetadataEngine`：移植 `addons/zeekr_log.py` 的列表/详情页字段修改；按 APK 哈希派生版本号。仅允许元数据明确指向、同一主机与路径、30 分钟内的下载替换。
- `ProxyServer`：原文件流式发送，支持 GET、HEAD、单段 Range、后缀 Range、If-Range 和 416。不会一次加载整个 APK。
- 日志只保留有限的运行状态与错误，不保存 HTTP 请求认证头、正文或带查询参数的完整 URL，不上传日志。

## GitHub Actions

工作流：`.github/workflows/build-android-gui.yml`。

构建使用 JDK 17、Gradle 8.11.1、Android SDK 35。执行单元测试、Android Lint、APK 构建与签名验证，并在 Android 15 模拟器安装和启动应用，保存界面截图。`codex/android-gui` 分支修改自动构建，也可在合并后手动运行。

在 Actions 完成的运行底部下载 `ZEELoad-Android-APK`，解压后将 APK 传到手机安装。该文件是完整的、调试签名的自用测试安装包；调试签名由 Actions 缓存尽量复用，缓存失效后可能需要卸载旧版再安装。没有把签名私钥或本机路径写入源码，也未附带任何待侧载的第三方 APK。

本地可使用 Android Studio 打开 `android/`，或安装 Gradle 后执行：

```sh
cd android
gradle :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
```

输出：`app/build/outputs/apk/debug/app-debug.apk`。本仓库提供标准 Gradle 工程，未附带 Wrapper JAR；Actions 不要求本地构建。

## 验证边界

自动测试覆盖 HTTP 范围、分块请求、边界冲突、下载地址门控、元数据改写、输入验证、Shell 参数引用、默认/旧版证书链、TLS 1.2/1.3 和大响应传输。模拟器启动检查验证 GUI 可以安装和打开。Root 热点转发、看护进程、具体手机 ROM 与实际车机商店安装流程需要用手机和车辆联调；模拟器检查不能代替实车结果。

证书素材来源与许可证见 `app/src/main/assets/THIRD_PARTY_NOTICES.txt`。沿用原仓库的自有车辆研究、自用约定。
