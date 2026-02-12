package anti.rusda.detector;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
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

    @SuppressWarnings("unused")
    private static native String nativeGetEnvVersion();
    private static native String[] nativeDetectMagisk();
    private static native String[] nativeDetectBootloader();
    private static native String[] nativeDetectSuspiciousFiles();
    private static native String[] nativeDetectZygiskInjection();
    private static native String[] nativeDetectEmulator(String hardware, String product, String device, String brand);
    private static native boolean nativeCheckPort(int port);
    private static native String[] nativeCheckCgroup();
    /** Verify APKs via syscall (assets/xposed_init) + modules.list; returns package names of Xposed modules */
    private static native String[] nativeVerifyXposedModules(String[] apkPaths, String[] packageNames);

    private final Context context;

    public EnvDetectionManager(Context context) {
        this.context = context;
    }

    public List<DetectionResult> runAllDetections() {
        List<DetectionResult> results = new ArrayList<>();
        results.add(detectBootloader());
        results.add(detectRoot());
        results.add(detectZygiskInjection());
        results.add(detectXposedModules());
        results.add(detectSuspiciousFiles());
        results.add(detectEmulator());
        results.add(detectKernelPatch());
        results.add(detectAdbEnhanced());
        results.add(checkProcessStatus());
        results.add(detectContainer());
        return results;
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

    /** 将 Native 层返回的 String[] 转为 DetectionResult。格式: [status, summary, detail0, ...] */
    private static DetectionResult fromNativeResult(String title, String[] raw,
            String normalSummary, String normalDetail) {
        if (raw == null || raw.length < 2) {
            return new DetectionResult(title, "Scan failed", DetectionResult.STATUS_WARNING);
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
     * Zygisk 注入检测：Smaps Private_Dirty + VMap 内存映射扫描（Zygisk/LSPosed/ZygiskNext 特征）。
     * LSPosed Hook 已合并至调试检测的 Xposed / Hook Framework。
     */
    private DetectionResult detectZygiskInjection() {
        return fromNativeResult("Zygisk Injection", nativeDetectZygiskInjection(),
                "No Zygisk injection detected", "Smaps and memory maps scan clean");
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

    private DetectionResult detectAdbEnhanced() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        if (context != null) {
            var resolver = context.getContentResolver();
            /* 开发者选项：Settings.Secure.development_settings_enabled（1=开启） */
            int devOptions = Settings.Secure.getInt(resolver, "development_settings_enabled", 0);
            int usbAdb = Settings.Global.getInt(resolver, "adb_enabled", 0);
            /* adb_wifi_enabled returns 0 if key not present (API 30+) */
            int wifiAdb = Settings.Global.getInt(resolver, "adb_wifi_enabled", 0);
            boolean port5555Open = nativeCheckPort(5555);

            details.add("Developer options: " + (devOptions == 1 ? "enabled" : "disabled"));
            details.add("USB ADB: " + (usbAdb == 1 ? "enabled" : "disabled"));
            details.add("WiFi ADB: " + (wifiAdb == 1 ? "enabled" : "disabled"));
            details.add("Port 5555: " + (port5555Open ? "open" : "closed"));

            if (devOptions == 1 || usbAdb == 1 || wifiAdb == 1 || port5555Open) {
                status = DetectionResult.STATUS_WARNING;
            }
        } else {
            details.add("No context for ADB check");
        }
        String summary = status == DetectionResult.STATUS_NORMAL
                ? "ADB debugging disabled, developer options off"
                : "Developer options or ADB enabled, or port 5555 open";
        /* warnOnly=true: 只做警告不扣分，部分设备需开启 ADB 做开发调试 */
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
