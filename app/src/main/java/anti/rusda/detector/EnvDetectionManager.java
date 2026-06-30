package anti.rusda.detector;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.security.MessageDigest;
import java.util.List;
import java.util.Set;

/**
 * 手机环境检测：Root、Magisk、Bootloader、模拟器、多开、可疑文件等。
 * 依赖 libenvdetect.so；Magisk、Bootloader、可疑文件、模拟器在 Native 层实现。
 */
public class EnvDetectionManager {

    private static final String[] MAGISK_PACKAGES = {
            "com.topjohnwu.magisk",
            "io.github.huskydg.magisk"
    };

    /** 风控应用：Xposed 模块 + MT Manager、Termux 等（可修改 APK、运行脚本） */
    private static final String[] DANGEROUS_APP_PACKAGES = {
            "bin.mt.plus",           // MT Manager
            "com.mi.mi.mtmanager",   // MT Manager (legacy)
            "com.termux"             // Termux
    };

    static {
        try {
            System.loadLibrary("envdetect");
        } catch (Throwable ignored) { }
    }

    /** 供 Application 启动时显式加载 envdetect，确保签名校验可调用 Native */
    public static void ensureEnvLoaded() {
        try {
            System.loadLibrary("envdetect");
        } catch (Throwable ignored) { }
    }

    @SuppressWarnings("unused")
    private static native String nativeGetEnvVersion();
    private static native String[] nativeDetectMagisk();
    private static native String[] nativeDetectBootloader();
    private static native String[] nativeDetectSuspiciousFiles();
    private static native String[] nativeDetectEmulator(String hardware, String product, String device, String brand);
    private static native boolean nativeCheckPort(int port);
    /** 多通道 Native ADB 检测（syscall）：端口、net/tcp、adbd 进程、sysfs；返回 String[] { status, summary, ... } */
    private static native String[] nativeDetectAdb();
    private static native String[] nativeCheckCgroup();
    /** Verify APKs via syscall (assets/xposed_init) + modules.list; returns package names of Xposed modules */
    private static native String[] nativeVerifyXposedModules(String[] apkPaths, String[] packageNames);
    /** 应用签名校验（防二次打包）：当前 APK 签名 SHA-256 与构建时预期值在 Native 层比对，返回 0=NORMAL，2=DANGER */
    private static native int nativeVerifyAppSignature(String sha256Hex);
    /** 从 APK 文件直接解析 v2/v3 签名块取证书 SHA-256（syscall 读文件，绕开可被 hook 的 PackageManager）；失败返回空串 */
    private static native String nativeGetApkCertSha256FromFile(String apkPath);
    /** APK fd / maps inode 一致性（揭穿 open(base.apk) 文件重定向）：1=一致，0=被重定向(DANGER)，<0=无法判定 */
    private static native int nativeApkFdInodeConsistent(String apkPath);
    /** seccomp prctl 与 /proc/self/status 一致性（揭穿伪造 status）：1=一致，0=不一致(DANGER)，<0=无法判定 */
    private static native int nativeSeccompConsistent();

    private final Context context;

    public EnvDetectionManager(Context context) {
        this.context = context;
    }

    public List<DetectionResult> runAllDetections() {
        List<DetectionResult> results = new ArrayList<>();
        results.add(detectAppSignature());
        results.add(detectApkTamper());
        results.add(detectSignatureBypass());
        results.add(detectBootloader());
        results.add(detectRoot());
        results.add(detectXposedModules());
        results.add(detectSuspiciousFiles());
        results.add(detectEmulator());
        results.add(detectCloudPhoneSensors());
        results.add(detectKernelPatch());
        results.add(detectAdbEnhanced());
        results.add(checkProcessStatus());
        results.add(detectContainer());
        return results;
    }

    /**
     * 应用签名校验（防二次打包）：与构建时注入的预期签名 SHA-256 在 Native 层比对。
     * 预期值仅在 release 构建时注入，Debug 不注入则跳过校验。
     */
    private DetectionResult detectAppSignature() {
        List<String> details = new ArrayList<>();
        if (context == null) {
            details.add("Context unavailable");
            return new DetectionResult("App Signature", "Check skipped", DetectionResult.STATUS_NORMAL, 15, details);
        }
        String sha256 = getAppSignatureSha256(context);
        if (sha256 == null || sha256.isEmpty()) {
            details.add("Could not get app signing certificate");
            return new DetectionResult("App Signature", "Check skipped", DetectionResult.STATUS_WARNING, 15, details);
        }
        try {
            int status = nativeVerifyAppSignature(sha256);
            if (status == 2) {
                details.add("Signature mismatch - app may be repackaged");
                details.add("Expected signing cert SHA-256 is embedded in release build");
                return new DetectionResult("App Signature", "Signature mismatch (possible repackage)", DetectionResult.STATUS_DANGER, 15, details);
            }
            details.add("Signing certificate matches expected (SHA-256)");
            return new DetectionResult("App Signature", "Signature verified", DetectionResult.STATUS_NORMAL, 15, details);
        } catch (Throwable t) {
            details.add("Verify error: " + (t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName()));
            return new DetectionResult("App Signature", "Check failed", DetectionResult.STATUS_WARNING, 15, details);
        }
    }

    /**
     * APK 防改包 / 反签名伪装（文件级，强于 {@link #detectAppSignature()}）。
     *
     * E1「App Signature」走 PackageManager，可被 CorePatch / 签名伪装类 Xposed 模块
     * hook 后返回原始签名 —— 改包重签后仍 PASS。本项直接用 Native syscall 从 APK
     * 文件解析 v2/v3 签名块取证书 SHA-256（绕开 PackageManager），两路交叉判定：
     *   1) 文件签名 != PackageManager 签名 → 有签名伪装模块在骗 Java API（DANGER）
     *   2) 文件签名 != 构建期注入预期 → 被人重签改包（DANGER，预期仅 release 注入）
     * 解析失败（v1-only / 非常规 ZIP）不误判，仅 warnOnly 提示。
     */
    private DetectionResult detectApkTamper() {
        List<String> details = new ArrayList<>();
        if (context == null) {
            details.add("Context unavailable");
            return new DetectionResult("APK Repack Guard", "Check skipped", DetectionResult.STATUS_NORMAL, 15, details, true);
        }
        String apkPath = null;
        try {
            ApplicationInfo ai = context.getApplicationInfo();
            if (ai != null) apkPath = ai.sourceDir;
        } catch (Throwable ignored) { }
        if (apkPath == null || apkPath.isEmpty()) {
            details.add("APK path unavailable");
            return new DetectionResult("APK Repack Guard", "Check skipped", DetectionResult.STATUS_WARNING, 15, details, true);
        }
        details.add("APK: " + apkPath);

        String fileSha;
        try {
            fileSha = nativeGetApkCertSha256FromFile(apkPath);
        } catch (Throwable t) {
            fileSha = null;
        }
        if (fileSha == null || fileSha.isEmpty()) {
            details.add("Could not parse v2/v3 signing block from APK file");
            /* 解析失败不下危险结论（v1-only 签名等），仅警示 */
            return new DetectionResult("APK Repack Guard", "Check skipped (no v2/v3 block)", DetectionResult.STATUS_WARNING, 15, details, true);
        }
        details.add("File-parsed cert SHA-256: " + fileSha);

        /* 1) 反签名伪装：文件真值 vs PackageManager 报告值 */
        String pmSha = getAppSignatureSha256(context);
        if (pmSha != null && !pmSha.isEmpty()) {
            details.add("PackageManager cert SHA-256: " + pmSha);
            if (!pmSha.equalsIgnoreCase(fileSha)) {
                details.add("MISMATCH: PackageManager signature != APK file signature");
                details.add("A signature-spoofing module (e.g. CorePatch) is faking the Java API");
                return new DetectionResult("APK Repack Guard", "Signature spoofing detected", DetectionResult.STATUS_DANGER, 15, details);
            }
            details.add("PackageManager matches file (no spoofing)");
        } else {
            details.add("PackageManager signature unavailable (file-level check only)");
        }

        /* 2) 防改包：文件真值 vs 构建期注入预期（Native 比对；debug 未注入则放行） */
        try {
            int verify = nativeVerifyAppSignature(fileSha);
            if (verify == 2) {
                details.add("File signature != expected - repackaged & re-signed with another key");
                return new DetectionResult("APK Repack Guard", "Repackaged (file signature mismatch)", DetectionResult.STATUS_DANGER, 15, details);
            }
            details.add("File signature matches expected (or expected not embedded in debug build)");
        } catch (Throwable t) {
            details.add("Expected-signature verify error: "
                    + (t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName()));
        }

        return new DetectionResult("APK Repack Guard", "APK signature intact (file-level, anti-spoof)", DetectionResult.STATUS_NORMAL, 15, details);
    }

    /**
     * 签名绕过足迹（结构级，参考 BypassApkSignature/testapp 的检测手法）。
     *
     * E1/E11 比对"签名值是否 = 预期"；过签框架（CorePatch / 自研重定向运行时）会从结构上
     * 动手脚，让各取证通道都返回原始签名值。本项不看签名值，而是查"绕过这件事本身"的足迹，
     * 覆盖 testapp 中 E1/E11 未做的技术：
     *   1) 多通道签名一致性：GET_SIGNATURES / GET_SIGNING_CERTIFICATES / getPackageArchiveInfo
     *      / Native 文件解析 四路取证，结果互相不一致 → 有通道被 hook 在骗人
     *   2) PackageInfo.CREATOR 真伪：真品是 boot 类加载器里的 android.content.pm.PackageInfo$1、
     *      零声明字段；CreatorProxy 仿冒会落在 App 类加载器 / 多出字段
     *   3) IPackageManager(mPM) 是否被换成动态 Proxy（PmProxy）
     *   4) appComponentFactory 完整性：进程内值 vs PM 报告值，过签常借 factory 做最早注入
     *   5) APK fd / maps inode 一致性（Native）：揭穿 open(base.apk) 文件重定向
     *   6) seccomp prctl vs /proc/self/status 一致性（Native）：揭穿伪造 status 隐藏过滤器
     * 任一硬信号命中 → DANGER；通道不可用一律按"跳过"处理，避免误报。
     */
    private DetectionResult detectSignatureBypass() {
        List<String> details = new ArrayList<>();
        if (context == null) {
            details.add("Context unavailable");
            return new DetectionResult("Signature Bypass Footprint", "Check skipped", DetectionResult.STATUS_NORMAL, 12, details);
        }
        boolean danger = false;
        final String pkg = context.getPackageName();
        final PackageManager pm = context.getPackageManager();

        /* 1) 多通道签名一致性：所有非空取证结果必须一致，否则有通道被伪装 */
        try {
            LinkedHashSet<String> shas = new LinkedHashSet<>();
            String s1 = shaFromPm(pm, pkg, PackageManager.GET_SIGNATURES, false);
            String s2 = shaFromPm(pm, pkg, PackageManager.GET_SIGNING_CERTIFICATES, true);
            String s3 = shaFromArchive(pm, context);
            String s4 = null;
            try { s4 = nativeGetApkCertSha256FromFile(context.getApplicationInfo().sourceDir); } catch (Throwable ignored) { }
            for (String s : new String[]{s1, s2, s3, s4}) {
                if (s != null && !s.isEmpty()) shas.add(s.toLowerCase(Locale.ROOT));
            }
            if (shas.size() > 1) {
                danger = true;
                details.add("MISMATCH across " + shas.size() + " signature channels - a hook is faking one route");
            } else if (shas.size() == 1) {
                details.add("Signature channels agree (" + shorten8(shas.iterator().next()) + ")");
            } else {
                details.add("No signature channel returned a value");
            }
        } catch (Throwable t) {
            details.add("channel check error: " + t.getClass().getSimpleName());
        }

        /* 2) PackageInfo.CREATOR 真伪（CreatorProxy 检测） */
        try {
            android.os.Parcelable.Creator<?> cr = PackageInfo.CREATOR;
            Class<?> c = cr.getClass();
            boolean nameOk = "android.content.pm.PackageInfo$1".equals(c.getName());
            boolean bootCl = (c.getClassLoader() == PackageInfo.class.getClassLoader());
            int nf = c.getDeclaredFields().length;
            if (!(nameOk && bootCl && nf == 0)) {
                danger = true;
                details.add("PackageInfo.CREATOR spoofed (CreatorProxy): name=" + nameOk + " bootCL=" + bootCl + " fields=" + nf);
            } else {
                details.add("PackageInfo.CREATOR genuine");
            }
        } catch (Throwable t) {
            details.add("CREATOR check error: " + t.getClass().getSimpleName());
        }

        /* 3) IPackageManager(mPM) 非动态 Proxy（PmProxy 检测） */
        try {
            java.lang.reflect.Field f = pm.getClass().getDeclaredField("mPM");
            f.setAccessible(true);
            Object mPM = f.get(pm);
            if (mPM != null) {
                String n = mPM.getClass().getName();
                boolean proxied = java.lang.reflect.Proxy.isProxyClass(mPM.getClass());
                if (proxied || !n.contains("IPackageManager")) {
                    danger = true;
                    details.add("IPackageManager proxied (PmProxy): mPM=" + shorten(n));
                } else {
                    details.add("IPackageManager genuine");
                }
            }
        } catch (Throwable t) {
            details.add("mPM check error: " + t.getClass().getSimpleName());
        }

        /* 4) appComponentFactory 完整性：进程内 vs PM 报告值 */
        try {
            String acfLocal = nz(context.getApplicationInfo().appComponentFactory);
            String acfPm = "";
            try { acfPm = nz(pm.getApplicationInfo(pkg, 0).appComponentFactory); } catch (Throwable ignored) { }
            if (!acfLocal.equals(acfPm)) {
                danger = true;
                details.add("appComponentFactory hijacked: local='" + shorten(acfLocal) + "' pm='" + shorten(acfPm) + "'");
            } else {
                details.add(acfLocal.isEmpty() ? "appComponentFactory: none" : "appComponentFactory: " + shorten(acfLocal));
            }
        } catch (Throwable t) {
            details.add("ACF check error: " + t.getClass().getSimpleName());
        }

        /* 5) Native fd / maps inode 一致性（文件重定向检测） */
        try {
            int r = nativeApkFdInodeConsistent(context.getApplicationInfo().sourceDir);
            if (r == 0) {
                danger = true;
                details.add("APK fd/maps inode MISMATCH - base.apk open() redirected");
            } else if (r == 1) {
                details.add("APK fd/maps inode consistent");
            } else {
                details.add("inode check unavailable (" + r + ")");
            }
        } catch (Throwable t) {
            details.add("inode check error: " + t.getClass().getSimpleName());
        }

        /* 6) Native seccomp prctl vs status 一致性（伪造 status 检测） */
        try {
            int r = nativeSeccompConsistent();
            if (r == 0) {
                danger = true;
                details.add("seccomp prctl vs status MISMATCH - /proc/self/status faked");
            } else if (r == 1) {
                details.add("seccomp prctl/status consistent");
            } else {
                details.add("seccomp check unavailable (" + r + ")");
            }
        } catch (Throwable t) {
            details.add("seccomp check error: " + t.getClass().getSimpleName());
        }

        if (danger) {
            return new DetectionResult("Signature Bypass Footprint", "Signature-bypass framework detected", DetectionResult.STATUS_DANGER, 12, details);
        }
        return new DetectionResult("Signature Bypass Footprint", "No signature-bypass footprint", DetectionResult.STATUS_NORMAL, 12, details);
    }

    private static String nz(String s) { return s == null ? "" : s; }

    private static String shorten(String s) {
        if (s == null) return "null";
        return s.length() > 28 ? s.substring(0, 28) + ".." : s;
    }

    private static String shorten8(String s) {
        if (s == null) return "null";
        return s.length() > 8 ? s.substring(0, 8) : s;
    }

    /** 经指定 PackageManager flag 取首签名证书 SHA-256；signingInfo=true 走 SigningInfo（API 28+）。失败返回 null。 */
    @SuppressWarnings("deprecation")
    private static String shaFromPm(PackageManager pm, String pkg, int flag, boolean signingInfo) {
        try {
            PackageInfo pi = pm.getPackageInfo(pkg, flag);
            if (pi == null) return null;
            if (signingInfo) {
                if (pi.signingInfo == null) return null;
                Signature[] sigs = pi.signingInfo.hasMultipleSigners()
                        ? pi.signingInfo.getApkContentsSigners()
                        : pi.signingInfo.getSigningCertificateHistory();
                if (sigs == null || sigs.length == 0) return null;
                return sha256Hex(sigs[0].toByteArray());
            }
            if (pi.signatures == null || pi.signatures.length == 0) return null;
            return sha256Hex(pi.signatures[0].toByteArray());
        } catch (Throwable t) {
            return null;
        }
    }

    /** 经 getPackageArchiveInfo 解析已安装 APK 文件取首签名证书 SHA-256。失败返回 null。 */
    @SuppressWarnings("deprecation")
    private static String shaFromArchive(PackageManager pm, Context ctx) {
        try {
            String apk = ctx.getApplicationInfo().sourceDir;
            PackageInfo pi = pm.getPackageArchiveInfo(apk, PackageManager.GET_SIGNATURES);
            if (pi == null || pi.signatures == null || pi.signatures.length == 0) return null;
            return sha256Hex(pi.signatures[0].toByteArray());
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * 获取当前应用签名证书的 SHA-256（小写十六进制 64 字符）。
     * API 28+ 使用 GET_SIGNING_CERTIFICATES，否则使用 GET_SIGNATURES。
     */
    public static String getAppSignatureSha256(Context context) {
        if (context == null) return null;
        try {
            PackageManager pm = context.getPackageManager();
            String packageName = context.getPackageName();
            PackageInfo info;
            if (Build.VERSION.SDK_INT >= 28) {
                info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                if (info == null || info.signingInfo == null) return null;
                Signature[] sigs = info.signingInfo.getApkContentsSigners();
                if (sigs == null || sigs.length == 0) return null;
                return sha256Hex(sigs[0].toByteArray());
            } else {
                info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                if (info == null || info.signatures == null || info.signatures.length == 0) return null;
                return sha256Hex(info.signatures[0].toByteArray());
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static String sha256Hex(byte[] data) {
        if (data == null) return null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(data);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 启动时签名校验（防二次打包）：在 Application.onCreate 中调用。
     * 若未配置预期签名（Debug 构建）或获取失败则放行；若签名不匹配则返回 false，调用方应结束进程。
     *
     * @return true 校验通过或跳过，false 签名不匹配（疑似二次打包）
     */
    public static boolean verifyAppSignatureAtStartup(Context context) {
        try {
            String sha = getAppSignatureSha256(context);
            if (sha == null || sha.isEmpty()) return true; /* 获取失败时放行，避免误杀 */
            int status = nativeVerifyAppSignature(sha);
            return status != 2;
        } catch (Throwable ignored) {
            return true;
        }
    }

    /**
     * Bootloader 检测：合并 Native 系统属性 + Key Attestation（TEE RootOfTrust）。
     * 包含 verifiedBootKey、deviceLocked、verifiedBootState、verifiedBootHash 等硬件级证明。
     */
    private DetectionResult detectBootloader() {
        /* 1. Native 层：AVB 系统属性（verifiedbootstate、flash.locked、veritymode、avb_version 等） */
        String[] nativeRaw = nativeDetectBootloader();
        int statusNat = DetectionResult.STATUS_NORMAL;
        List<String> details = new ArrayList<>();
        details.add("═══ AVB (System Properties) ═══");
        boolean nativeOemEnabled = false;
        if (nativeRaw != null && nativeRaw.length >= 2) {
            try {
                statusNat = Integer.parseInt(nativeRaw[0]);
            } catch (NumberFormatException ignored) { }
            if (nativeRaw.length > 2) {
                details.addAll(Arrays.asList(Arrays.copyOfRange(nativeRaw, 2, nativeRaw.length)));
                for (int i = 2; i < nativeRaw.length; i++) {
                    if (nativeRaw[i] != null && nativeRaw[i].contains("OEM unlock")) {
                        nativeOemEnabled = true;
                        break;
                    }
                }
            } else {
                details.add("verifiedbootstate, flash.locked, veritymode, avb_version, etc.");
            }
        } else {
            details.add("Native bootloader check unavailable");
        }

        /* 1.5 OEM 解锁交叉验证：Native sys.oem_unlock_allowed vs Java Settings.Global
         * 注意：sys.oem_unlock_allowed 与 oem_unlock_enabled 在多数设备上对普通应用不可读（系统限制），
         * 两者可能常为 0/空，非检测逻辑错误。 */
        if (context != null) {
            details.add("═══ OEM Unlock Cross-Verify ═══");
            int oemUnlockJava = -1;
            try {
                android.content.ContentResolver cr = context.getContentResolver();
                oemUnlockJava = Settings.Global.getInt(cr, "oem_unlocking_enabled", -1);
                if (oemUnlockJava < 0) {
                    oemUnlockJava = Settings.Global.getInt(cr, "oem_unlock_enabled", -1);
                }
            } catch (SecurityException ignored) {
                oemUnlockJava = -1;
            }
            boolean javaReadable = (oemUnlockJava >= 0);
            boolean javaOemEnabled = (oemUnlockJava == 1);
            String javaStr = !javaReadable ? "unreadable (system restricted)" : (javaOemEnabled ? "1 (enabled)" : "0 (disabled)");
            details.add("Settings.Global.oem_unlock*: " + javaStr);
            details.add("Native sys.oem_unlock_allowed: " + (nativeOemEnabled ? "1 (enabled)" : "0 or unreadable"));
            if (javaReadable && nativeOemEnabled != javaOemEnabled) {
                details.add("OEM unlock cross-verify mismatch (possible hook or OEM-specific semantics)");
                if (statusNat < DetectionResult.STATUS_WARNING) statusNat = DetectionResult.STATUS_WARNING;
            }
            if (!javaReadable && !nativeOemEnabled) {
                details.add("Note: OEM unlock status often restricted on stock devices; Key Attestation deviceLocked is more reliable.");
            }
        }

        /* 2. Key Attestation：TEE RootOfTrust（deviceLocked、verifiedBootState、verifiedBootKey、verifiedBootHash） */
        String[] attestRaw = KeyAttestationHelper.runAttestationSync();
        int statusAtt = DetectionResult.STATUS_NORMAL;
        if (attestRaw != null && attestRaw.length >= 2) {
            try {
                statusAtt = Integer.parseInt(attestRaw[0]);
            } catch (NumberFormatException ignored) { }
            details.add("═══ Key Attestation (TEE RootOfTrust) ═══");
            if (attestRaw.length > 2) {
                details.addAll(Arrays.asList(Arrays.copyOfRange(attestRaw, 2, attestRaw.length)));
            } else {
                details.add(attestRaw[1]);
            }
        } else {
            details.add("═══ Key Attestation (TEE RootOfTrust) ═══");
            details.add("Key attestation unavailable or failed");
            statusAtt = DetectionResult.STATUS_WARNING;
        }

        /* 取最严重状态：DANGER > WARNING > NORMAL */
        int status = Math.max(statusNat, statusAtt);

        String summary;
        if (status == DetectionResult.STATUS_DANGER) {
            summary = "Bootloader unlocked or boot may be patched";
        } else if (status == DetectionResult.STATUS_WARNING) {
            summary = "Bootloader state uncertain or self-signed";
        } else {
            summary = "Bootloader locked, boot verified";
        }

        DetectionResult result = new DetectionResult("Bootloader", summary, status, 15);
        result.setDetails(details.isEmpty() ? Collections.singletonList("No issues detected") : details);
        return result;
    }

    /** 将 Native 层返回的 String[] 转为 DetectionResult。格式: [status, summary, detail0, ...]；无法执行时显示 Check skipped、不扣分 */
    private static DetectionResult fromNativeResult(String title, String[] raw,
            String normalSummary, String normalDetail) {
        if (raw == null || raw.length < 2) {
            return new DetectionResult(title, "Check skipped", DetectionResult.STATUS_NORMAL);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Arrays.asList(Arrays.copyOfRange(raw, 2, raw.length))
                : Collections.singletonList(normalDetail);
        if (details.size() == 1 && "No issues detected".equals(details.get(0))) {
            details = Collections.singletonList(normalDetail);
        }
        DetectionResult result = new DetectionResult(title, summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectRoot() {
        String[] nativeRaw = nativeDetectMagisk();
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        if (nativeRaw != null && nativeRaw.length >= 2) {
            try {
                status = Integer.parseInt(nativeRaw[0]);
            } catch (NumberFormatException ignored) { }
            if (nativeRaw.length > 2) {
                details.addAll(Arrays.asList(Arrays.copyOfRange(nativeRaw, 2, nativeRaw.length)));
            }
        }

        if (context != null) {
            List<String> magiskApps = checkMagiskPackages();
            if (!magiskApps.isEmpty()) {
                status = DetectionResult.STATUS_DANGER;
                details.addAll(magiskApps);
            }
        }

        String summary = (status == DetectionResult.STATUS_DANGER || !details.isEmpty())
                ? "Magisk or root indicator(s) found"
                : "No Magisk detected";
        DetectionResult result = new DetectionResult("Magisk / Root", summary, status, 12);
        result.setDetails(details.isEmpty() ? Collections.singletonList("No root binaries or Magisk detected") : details);
        return result;
    }

    private List<String> checkMagiskPackages() {
        List<String> found = new ArrayList<>();
        if (context == null) return found;
        PackageManager pm = context.getPackageManager();
        if (pm == null) return found;
        try {
            for (String pkg : MAGISK_PACKAGES) {
                try {
                    pm.getPackageInfo(pkg, 0);
                    found.add("Magisk app installed: " + pkg);
                } catch (PackageManager.NameNotFoundException ignored) {
                    // not installed
                }
            }
        } catch (Exception ignored) { }
        return found;
    }

    /**
     * Dangerous Apps: 多种方式检测 Xposed 模块，降低 API 被 hook 的影响。
     * 1) Java meta-data (xposedmodule) - 可被 hook；
     * 2) Native 解析 APK 的 assets/xposed_init - syscall，难 hook；
     * 3) Native 读取 modules.list - Root 时有效。
     * 仅警告不扣分（warnOnly）。
     */
    private DetectionResult detectXposedModules() {
        List<String> details = new ArrayList<>();
        Set<String> dangerousPkgs = new LinkedHashSet<>();
        int status = DetectionResult.STATUS_NORMAL;

        if (context == null) {
            details.add("No context");
            return new DetectionResult("Dangerous Apps", "Context unavailable", status, 5, details, true);
        }

        PackageManager pm = context.getPackageManager();
        if (pm == null) {
            details.add("PackageManager unavailable");
            return new DetectionResult("Dangerous Apps", "PackageManager unavailable", status, 5, details, true);
        }

        List<String> apkPaths = new ArrayList<>();
        List<String> pkgNames = new ArrayList<>();

        try {
            /* 方式1: getInstalledPackages - 可能被 Hide My Applist 等隐藏 */
            List<PackageInfo> packages = pm.getInstalledPackages(PackageManager.GET_META_DATA);
            for (PackageInfo pkg : packages) {
                if (pkg == null || pkg.applicationInfo == null) continue;
                ApplicationInfo appInfo = pkg.applicationInfo;
                if (isXposedModule(appInfo.metaData) || isDangerousAppPackage(pkg.packageName)) {
                    dangerousPkgs.add(pkg.packageName);
                }
                String src = appInfo.sourceDir;
                if (src != null && !src.isEmpty()) {
                    apkPaths.add(src);
                    pkgNames.add(pkg.packageName);
                }
            }

            /* 方式2: queryIntentActivities - 与方式1交叉验证，发现被隐藏的应用 */
            Intent launcher = new Intent(Intent.ACTION_MAIN, null);
            launcher.addCategory(Intent.CATEGORY_LAUNCHER);
            List<ResolveInfo> apps = pm.queryIntentActivities(launcher, 0);
            if (apps != null) {
                for (ResolveInfo ri : apps) {
                    if (ri == null || ri.activityInfo == null) continue;
                    String pkg = ri.activityInfo.packageName;
                    ApplicationInfo appInfo = ri.activityInfo.applicationInfo;
                    if (appInfo != null && appInfo.sourceDir != null && !appInfo.sourceDir.isEmpty()) {
                        if (!apkPaths.contains(appInfo.sourceDir)) {
                            apkPaths.add(appInfo.sourceDir);
                            pkgNames.add(pkg);
                        }
                        if (isXposedModule(appInfo.metaData) || isDangerousAppPackage(pkg)) {
                            dangerousPkgs.add(pkg);
                        }
                    }
                }
            }

            /* 方式3: Native 校验 - syscall 解析 APK 的 assets/xposed_init + modules.list，绕过 metaData hook */
            if (!apkPaths.isEmpty() && apkPaths.size() == pkgNames.size()) {
                try {
                    String[] nativeFound = nativeVerifyXposedModules(
                            apkPaths.toArray(new String[0]),
                            pkgNames.toArray(new String[0]));
                    if (nativeFound != null) {
                        for (String p : nativeFound) {
                            if (p != null && !p.isEmpty()) dangerousPkgs.add(p);
                        }
                    }
                } catch (Throwable ignored) { /* Native 调用失败时仍使用 Java 结果 */ }
            }
        } catch (Exception e) {
            details.add("Scan error: " + e.getMessage());
            status = DetectionResult.STATUS_WARNING;
        }

        for (String p : dangerousPkgs) {
            details.add("Dangerous app: " + p);
        }
        if (!dangerousPkgs.isEmpty()) status = DetectionResult.STATUS_WARNING;

        if (details.isEmpty()) {
            details.add("No dangerous apps found");
        }

        String summary = status == DetectionResult.STATUS_NORMAL
                ? "No dangerous apps found"
                : "Dangerous app(s) detected";
        return new DetectionResult("Dangerous Apps", summary, status, 5, details, true);  // warnOnly
    }

    /** 检查 meta-data 是否声明为 Xposed 模块（xposedmodule / xposed_module） */
    private static boolean isXposedModule(Bundle metaData) {
        if (metaData == null) return false;
        Object v1 = metaData.get("xposedmodule");
        Object v2 = metaData.get("xposed_module");
        return isTruthy(v1) || isTruthy(v2);
    }

    private static boolean isTruthy(Object v) {
        if (v == null) return false;
        if (Boolean.TRUE.equals(v)) return true;
        return "true".equalsIgnoreCase(String.valueOf(v));
    }

    /** 检查是否风控应用（MT Manager、Termux 等） */
    private static boolean isDangerousAppPackage(String pkg) {
        if (pkg == null || pkg.isEmpty()) return false;
        for (String d : DANGEROUS_APP_PACKAGES) {
            if (d.equals(pkg)) return true;
        }
        return false;
    }

    private DetectionResult detectKernelPatch() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        String patchLevel = Build.VERSION.SECURITY_PATCH;
        if (patchLevel != null && !patchLevel.isEmpty()) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
                Date patchDate = sdf.parse(patchLevel);
                if (patchDate != null) {
                    long monthsAgo = (System.currentTimeMillis() - patchDate.getTime()) / (30L * 24 * 60 * 60 * 1000);
                    details.add("Security patch: " + patchLevel);
                    details.add("Approx. " + monthsAgo + " months old");
                    if (monthsAgo >= 24) {
                        status = DetectionResult.STATUS_WARNING;
                        details.add("Kernel patch over 24 months old - recommend update (not indicative of gray market)");
                    } else if (monthsAgo >= 12) {
                        status = DetectionResult.STATUS_WARNING;
                        details.add("Kernel patch over 12 months old");
                    }
                }
            } catch (ParseException e) {
                details.add("Could not parse patch date: " + patchLevel);
            }
        } else {
            details.add("Security patch level unknown");
        }
        String summary = status == DetectionResult.STATUS_NORMAL
                ? "Kernel patch level acceptable"
                : "Kernel patch outdated (12+ months) - warning only, not indicative of gray market";
        return new DetectionResult("Kernel Patch", summary, status, 10, details, true);  // warnOnly：过期仅警告不扣分
    }

    /**
     * exec 执行命令并读取首行输出，绕过 ContentResolver/Settings API hook。
     * 用于 getprop、settings get 等替代路径。
     */
    private static String execReadFirstLine(String[] cmd) {
        try {
            java.lang.Process p = Runtime.getRuntime().exec(cmd);
            try (BufferedReader r = new BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
                String line = r.readLine();
                p.waitFor();
                return line != null ? line.trim() : "";
            }
        } catch (Throwable ignored) {
            return "";
        }
    }

    private DetectionResult detectAdbEnhanced() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        /* 1. Native 多通道检测（syscall，抗 hook） */
        String[] nativeRaw = nativeDetectAdb();
        if (nativeRaw != null && nativeRaw.length >= 2) {
            try {
                int natStatus = Integer.parseInt(nativeRaw[0]);
                if (natStatus == 1) status = DetectionResult.STATUS_WARNING;
                details.add("═══ Native (syscall) ═══");
                if (nativeRaw.length > 2) {
                    for (int i = 2; i < nativeRaw.length; i++) {
                        if (nativeRaw[i] != null && !nativeRaw[i].isEmpty()) {
                            details.add(nativeRaw[i]);
                        }
                    }
                } else {
                    details.add("No ADB indicators (port/net/tcp/adbd/sysfs)");
                }
            } catch (NumberFormatException ignored) { }
        }

        /* 2. Java Settings API（易被 hook，保留作兼容） */
        if (context != null) {
            details.add("═══ Settings API ═══");
            try {
                var resolver = context.getContentResolver();
                int devOptions = Settings.Secure.getInt(resolver, "development_settings_enabled", 0);
                int usbAdb = Settings.Global.getInt(resolver, "adb_enabled", 0);
                int wifiAdb = Settings.Global.getInt(resolver, "adb_wifi_enabled", 0);

                details.add("Developer options: " + (devOptions == 1 ? "enabled" : "disabled"));
                details.add("USB ADB: " + (usbAdb == 1 ? "enabled" : "disabled"));
                details.add("WiFi ADB: " + (wifiAdb == 1 ? "enabled" : "disabled"));

                if (devOptions == 1 || usbAdb == 1 || wifiAdb == 1) status = DetectionResult.STATUS_WARNING;
            } catch (SecurityException ignored) {
                details.add("Settings restricted");
            }
        }

        /* 3. exec 替代路径（绕过 ContentResolver hook；使用完整路径以提高可用性） */
        details.add("═══ Exec fallback ═══");
        String adbdSvc = execReadFirstLine(new String[]{"/system/bin/getprop", "init.svc.adbd"});
        String adbEnabled = execReadFirstLine(new String[]{"/system/bin/settings", "get", "global", "adb_enabled"});
        String adbWifi = execReadFirstLine(new String[]{"/system/bin/settings", "get", "global", "adb_wifi_enabled"});
        String devOpts = execReadFirstLine(new String[]{"/system/bin/settings", "get", "secure", "development_settings_enabled"});

        boolean adbdRunning = "running".equalsIgnoreCase(adbdSvc);
        boolean execAdbOn = "1".equals(adbEnabled);
        boolean execWifiOn = "1".equals(adbWifi);
        boolean execDevOn = "1".equals(devOpts);

        details.add("getprop init.svc.adbd: " + (adbdSvc.isEmpty() ? "N/A" : adbdSvc));
        details.add("settings adb_enabled: " + (adbEnabled.isEmpty() ? "N/A" : adbEnabled));
        details.add("settings adb_wifi_enabled: " + (adbWifi.isEmpty() ? "N/A" : adbWifi));
        details.add("settings development_settings_enabled: " + (devOpts.isEmpty() ? "N/A" : devOpts));

        if (adbdRunning || execAdbOn || execWifiOn || execDevOn) status = DetectionResult.STATUS_WARNING;

        String summary = status == DetectionResult.STATUS_NORMAL
                ? "ADB debugging disabled, developer options off"
                : "Developer options or ADB enabled (multi-channel)";
        return new DetectionResult("ADB Debug", summary, status, 5, details, true);
    }

    private DetectionResult detectSuspiciousFiles() {
        return fromNativeResult("Suspicious Files", nativeDetectSuspiciousFiles(),
                "No suspicious files detected", "No Frida-related or debug files found");
    }

    private DetectionResult detectEmulator() {
        String[] raw = nativeDetectEmulator(
                Build.HARDWARE, Build.PRODUCT, Build.DEVICE, Build.BRAND);
        return fromNativeResult("Emulator", raw,
                "Running on physical device", "Device appears to be physical");
    }

    /** 传感器厂商/名称里的模拟器/云手机特征关键词 */
    private static final String[] FAKE_SENSOR_KEYWORDS = {
            "goldfish", "ranchu", "aosp", "the android open source project",
            "genymotion", "virtualbox", "vbox", "generic", "qemu",
            "cuttlefish", "vsoc", "redroid", "nox", "ldplayer", "mumu", "bluestacks"
    };

    /**
     * 云手机 / 传感器 / 硬件真实性检测（运行时角度，区别于基于 Build/文件的 Emulator 项）。
     *
     * 物理真机有一整套真实传感器（加速度计几乎必有，通常还有陀螺仪/磁力计/光线/距离等十余个），
     * 电池有真实温度/电压。云手机与模拟器往往：传感器极少或缺加速度计、传感器厂商名为
     * Goldfish/AOSP 等、电池温度/电压恒为 0。聚合多信号判定。WARNING 级（与 Emulator 一致）。
     */
    private DetectionResult detectCloudPhoneSensors() {
        List<String> details = new ArrayList<>();
        int strong = 0, weak = 0;
        if (context == null) {
            details.add("Context unavailable");
            return new DetectionResult("Cloud Phone / Sensors", "Check skipped", DetectionResult.STATUS_NORMAL, 8, details, true);
        }

        /* 1. 传感器 */
        try {
            SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            if (sm != null) {
                List<Sensor> all = sm.getSensorList(Sensor.TYPE_ALL);
                int count = all != null ? all.size() : 0;
                details.add("Sensor count: " + count);
                boolean hasAccel = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null;
                boolean hasGyro = sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null;
                details.add("Accelerometer: " + (hasAccel ? "present" : "MISSING") + ", Gyroscope: " + (hasGyro ? "present" : "missing"));

                if (!hasAccel) { details.add("No accelerometer - almost never a real phone"); strong++; }
                if (count == 0) { details.add("Zero sensors reported"); strong++; }
                else if (count < 5) { details.add("Very few sensors (<5)"); weak++; }
                if (!hasGyro) weak++;

                /* 传感器厂商/名称特征 */
                if (all != null) {
                    String hit = null;
                    for (Sensor s : all) {
                        String blob = ((s.getVendor() == null ? "" : s.getVendor()) + " " +
                                       (s.getName() == null ? "" : s.getName())).toLowerCase(Locale.US);
                        for (String kw : FAKE_SENSOR_KEYWORDS) {
                            if (blob.contains(kw)) { hit = s.getName() + " / " + s.getVendor(); break; }
                        }
                        if (hit != null) break;
                    }
                    if (hit != null) { details.add("Emulator-style sensor: " + hit); strong++; }
                }
            } else {
                details.add("SensorManager unavailable");
                weak++;
            }
        } catch (Throwable t) {
            details.add("Sensor check error: " + t.getClass().getSimpleName());
        }

        /* 2. 电池硬件（sticky ACTION_BATTERY_CHANGED，无需权限） */
        try {
            Intent bat = context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if (bat != null) {
                int temp = bat.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1);   // 0.1°C
                int volt = bat.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1);        // mV
                String tech = bat.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY);
                details.add("Battery: temp=" + (temp / 10.0) + "°C, voltage=" + volt + "mV, tech=" + tech);
                if (temp <= 0 && volt <= 0) { details.add("Battery temp & voltage both zero (virtualized?)"); weak++; }
                if (tech == null || tech.isEmpty() || "unknown".equalsIgnoreCase(tech)) weak++;
            } else {
                details.add("Battery info unavailable");
            }
        } catch (Throwable t) {
            details.add("Battery check error: " + t.getClass().getSimpleName());
        }

        /* 3. 聚合：任一强信号，或 ≥2 弱信号 → 疑似云手机/模拟器 */
        boolean suspect = (strong >= 1) || (weak >= 2);
        int status = suspect ? DetectionResult.STATUS_WARNING : DetectionResult.STATUS_NORMAL;
        String summary = suspect
                ? "Cloud phone / emulator indicators (sensors/hardware)"
                : "Sensors & hardware look like a real device";
        if (!suspect) details.add("No strong virtualized-hardware indicators");
        return new DetectionResult("Cloud Phone / Sensors", summary, status, 8, details);
    }

    private DetectionResult checkProcessStatus() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        try {
            details.add("Process ID: " + Process.myPid());
            if (context != null) {
                String packageName = context.getPackageName();
                details.add("Package: " + packageName);
                if (packageName != null && (packageName.contains(":") || packageName.toLowerCase().contains("dual"))) {
                    details.add("Package name suggests dual app");
                    status = DetectionResult.STATUS_WARNING;
                }
                if (context.getFilesDir() != null) {
                    String dataDir = context.getFilesDir().getAbsolutePath();
                    details.add("Files dir: " + dataDir);
                    if (dataDir.contains("parallel") || dataDir.contains("dual") || dataDir.contains("clone") || dataDir.contains("multi")) {
                        details.add("Suspicious data directory path");
                        status = DetectionResult.STATUS_WARNING;
                    }
                }
            }
        } catch (Exception e) {
            details.add("Error: " + e.getMessage());
        }
        return new DetectionResult(
                "Multi-instance",
                status == DetectionResult.STATUS_NORMAL ? "No multi-instance detected" : "Multi-instance app detected",
                status,
                5,
                details
        );
    }

    private static final String[] CONTAINER_APP_PACKAGES = {
            "io.va.exposed",            // VirtualApp
            "com.lody.virtual",         // VirtualApp legacy
            "me.weishu.exp",            // Tai Chi
            "com.parallel.space.lite",  // Parallel Space
            "com.excelliance.dualaid"   // Dual Space
    };

    private DetectionResult detectContainer() {
        List<String> issues = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        /* 1. Package name vs process name (cmdline) */
        if (context != null) {
            String pkgName = context.getPackageName();
            String procName = getProcessName();
            if (pkgName != null && procName != null && !pkgName.equals(procName)) {
                issues.add("Package mismatch: " + pkgName + " vs " + procName);
                status = DetectionResult.STATUS_DANGER;
            }
        }

        /* 2. Container app packages */
        if (context != null) {
            PackageManager pm = context.getPackageManager();
            if (pm != null) {
                for (String pkg : CONTAINER_APP_PACKAGES) {
                    try {
                        pm.getPackageInfo(pkg, 0);
                        issues.add("Container detected: " + pkg);
                        status = DetectionResult.STATUS_DANGER;
                    } catch (PackageManager.NameNotFoundException ignored) {
                        // not installed
                    }
                }
            }
        }

        /* 3. Native cgroup check */
        String[] cgroupResult = nativeCheckCgroup();
        if (cgroupResult != null && cgroupResult.length >= 2) {
            try {
                int cgroupStatus = Integer.parseInt(cgroupResult[0]);
                if (cgroupStatus == DetectionResult.STATUS_DANGER && cgroupResult.length > 2) {
                    for (int i = 2; i < cgroupResult.length; i++) {
                        issues.add(cgroupResult[i]);
                    }
                    status = DetectionResult.STATUS_DANGER;
                }
            } catch (NumberFormatException ignored) { }
        }

        return new DetectionResult(
                "Container / Virtualization",
                status == DetectionResult.STATUS_NORMAL ? "No container detected" : "Container or virtualization detected",
                status,
                8,
                issues.isEmpty() ? Collections.singletonList("No container or virtual app detected") : issues
        );
    }

    private static String getProcessName() {
        try {
            File f = new File("/proc/self/cmdline");
            if (f.exists()) {
                try (BufferedReader r = new BufferedReader(new FileReader(f))) {
                    String line = r.readLine();
                    if (line != null) {
                        return line.replace('\0', ' ').trim();
                    }
                }
            }
        } catch (IOException ignored) {
        }
        return null;
    }

}
