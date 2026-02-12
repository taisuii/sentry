package anti.rusda.detector;

import android.content.Context;
import android.os.Debug;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 调试相关检测：Frida、Xposed、IDA/ptrace 附加、端口等。
 * 依赖 libantidebug.so（端口扫描在 Native 层）。
 */
public class DebugDetectionManager {

    /** Frida 线程检测在 Native 层（syscall），防 Hook */
    private static native String[] nativeDetectFridaThreads();
    /** 端口扫描在 Native 层（syscall），结果由此方法返回 */
    private static native String[] nativeGetFridaPortScanResult();
    /** 内存签名扫描在 Native 层（syscall），防 Hook */
    private static native String[] nativeGetMemorySignatureResult();
    /** Native Hook 检测（内联/PLT/GOT），增强 Xposed 检测 */
    private static native String[] nativeDetectHook();
    /** Native Xposed 特征路径与 /proc/self/fd（linjector 等）检测 */
    private static native String[] nativeDetectXposedPaths();

    public static void ensureNativeLoaded() {
        try {
            System.loadLibrary("antidebug");
        } catch (Throwable ignored) { }
    }

    /** 无 Context 时应用列表检测不执行；建议使用 {@link #runAllDetections(Context)}。 */
    public List<DetectionResult> runAllDetections() {
        return runAllDetections(null);
    }

    public List<DetectionResult> runAllDetections(Context context) {
        ensureNativeLoaded();
        List<DetectionResult> results = new ArrayList<>();
        results.add(detectFridaThreads());
        results.add(detectFridaPorts());
        results.add(detectMemorySignatures());
        results.add(detectNamedPipes());
        results.add(detectPtraceStatus());
        results.add(detectDebuggerAttached());
        results.add(checkLibraryIntegrity(context));
        return results;
    }

    /** Native 实现（syscall），防 Java 层 Hook */
    private DetectionResult detectFridaThreads() {
        String[] raw = nativeDetectFridaThreads();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Frida Threads", "Scan failed", DetectionResult.STATUS_WARNING);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Arrays.asList(Arrays.copyOfRange(raw, 2, raw.length))
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("Frida Threads", summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectFridaPorts() {
        String[] raw = nativeGetFridaPortScanResult();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Frida Ports", "Scan failed", DetectionResult.STATUS_WARNING);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Arrays.asList(Arrays.copyOfRange(raw, 2, raw.length))
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("Frida Ports", summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectMemorySignatures() {
        String[] raw = nativeGetMemorySignatureResult();
        if (raw == null || raw.length < 2) {
            return new DetectionResult("Memory Signatures", "Scan failed", DetectionResult.STATUS_WARNING);
        }
        int status = DetectionResult.STATUS_NORMAL;
        try {
            status = Integer.parseInt(raw[0]);
        } catch (NumberFormatException ignored) { }
        String summary = raw[1];
        List<String> details = raw.length > 2
                ? Arrays.asList(Arrays.copyOfRange(raw, 2, raw.length))
                : Collections.emptyList();
        DetectionResult result = new DetectionResult("Memory Signatures", summary, status);
        result.setDetails(details);
        return result;
    }

    private DetectionResult detectNamedPipes() {
        List<String> pipes = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        try {
            String unixContent = readFileContent("/proc/self/net/unix");
            for (String line : unixContent.split("\\n")) {
                if (line.toLowerCase().contains("frida") || line.toLowerCase().contains("gmain") || line.toLowerCase().contains("gdbus")) {
                    pipes.add(line.trim());
                    status = DetectionResult.STATUS_DANGER;
                }
            }
        } catch (Exception e) {
            pipes.add("Error checking pipes: " + e.getMessage());
        }
        DetectionResult result = new DetectionResult(
                "Named Pipes",
                pipes.isEmpty() ? "No suspicious pipes detected" : pipes.size() + " suspicious pipe(s) detected",
                status
        );
        result.setDetails(pipes.isEmpty() ? Collections.singletonList("No Frida-related named pipes found") : pipes);
        return result;
    }

    private DetectionResult detectPtraceStatus() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        try {
            String statusContent = readFileContent("/proc/self/status");
            for (String line : statusContent.split("\\n")) {
                if (line.startsWith("TracerPid:")) {
                    String value = line.substring(line.indexOf(":") + 1).trim();
                    int tracerPid = Integer.parseInt(value);
                    if (tracerPid != 0) {
                        details.add("Process is being traced by PID: " + tracerPid);
                        status = DetectionResult.STATUS_DANGER;
                    } else {
                        details.add("No tracer process detected (TracerPid: 0)");
                    }
                }
                if (line.startsWith("State:")) {
                    details.add("Process state: " + line.substring(line.indexOf(":") + 1).trim());
                }
            }
        } catch (Exception e) {
            details.add("Error reading process status: " + e.getMessage());
        }
        return new DetectionResult(
                "Ptrace / IDA Attach",
                status == DetectionResult.STATUS_NORMAL ? "Process is not being traced" : "Process is being traced!",
                status,
                details
        );
    }

    private DetectionResult detectDebuggerAttached() {
        boolean isDebug = Debug.isDebuggerConnected();
        List<String> details = new ArrayList<>();
        details.add(isDebug ? "Debugger is currently connected" : "No debugger detected");
        int status = isDebug ? DetectionResult.STATUS_DANGER : DetectionResult.STATUS_NORMAL;
        return new DetectionResult(
                "Debugger Attached",
                status == DetectionResult.STATUS_NORMAL ? "No debugger detected" : "Debugger detected",
                status,
                details
        );
    }

    /** Java 多维度检测 + Native 内联/PLT/路径 检测。不检测「应用安装」：安装 LSPosed Manager ≠ 当前进程被 hook。 */
    private DetectionResult checkLibraryIntegrity(Context context) {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        /* 1. Java: XposedBridge 类检测 */
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            details.add("Xposed framework detected (Class.forName)");
            status = DetectionResult.STATUS_DANGER;
        } catch (ClassNotFoundException e) {
            details.add("Xposed framework not detected (Class.forName)");
        }

        /* 2. Java: 堆栈检测 — 自造异常检查堆栈中是否包含 Xposed 特征类 */
        if (status != DetectionResult.STATUS_DANGER && detectXposedInStack()) {
            details.add("Xposed framework detected (stack trace)");
            status = DetectionResult.STATUS_DANGER;
        }

        /* 3. Java: 反射检测 XposedHelpers / findAndHookMethod */
        if (status != DetectionResult.STATUS_DANGER && detectXposedByReflection(details)) {
            status = DetectionResult.STATUS_DANGER;
        }

        /* 4. Java: ClassLoader 实例检测（LSPosed InMemoryClassLoader、LspModuleClassLoader）— 检测当前进程是否被 hook，非「应用安装」 */
        if (status != DetectionResult.STATUS_DANGER) {
            List<String> classloaderDetails = detectSuspiciousClassLoaders();
            if (!classloaderDetails.isEmpty()) {
                details.addAll(classloaderDetails);
                status = DetectionResult.STATUS_DANGER;
            }
        }

        /* 5. Native: Xposed 特征路径与 fd（linjector 等） */
        String[] pathRaw = nativeDetectXposedPaths();
        if (pathRaw != null && pathRaw.length >= 2) {
            try {
                if (Integer.parseInt(pathRaw[0]) == DetectionResult.STATUS_DANGER) {
                    for (int i = 2; i < pathRaw.length; i++) {
                        details.add(pathRaw[i]);
                    }
                    status = DetectionResult.STATUS_DANGER;
                }
            } catch (NumberFormatException ignored) { }
        }

        /* 6. Native: 内联 Hook、PLT/GOT、libc 完整性 */
        String[] hookRaw = nativeDetectHook();
        if (hookRaw != null && hookRaw.length >= 2) {
            try {
                int hookStatus = Integer.parseInt(hookRaw[0]);
                if (hookStatus == DetectionResult.STATUS_DANGER) {
                    details.add(hookRaw.length > 2 ? hookRaw[2] : "Native hook/integrity check failed");
                    status = DetectionResult.STATUS_DANGER;
                }
            } catch (NumberFormatException ignored) { }
        }

        return new DetectionResult(
                "Xposed / Hook Framework",
                status == DetectionResult.STATUS_NORMAL ? "No Xposed detected" : "Framework modification detected",
                status,
                details
        );
    }

    /** 通过自造异常检查堆栈中是否包含 Xposed 特征类名 */
    private static boolean detectXposedInStack() {
        try {
            throw new RuntimeException("xposed_stack_check");
        } catch (Throwable t) {
            for (StackTraceElement e : t.getStackTrace()) {
                String cn = e.getClassName();
                if (cn != null && (cn.contains("de.robv.android.xposed.XposedBridge")
                        || cn.contains("de.robv.android.xposed.XposedHelpers")
                        || cn.contains("org.lsposed"))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 反射检测 XposedHelpers / XposedBridge 中的 findAndHookMethod 等关键方法是否存在 */
    private static boolean detectXposedByReflection(List<String> details) {
        String[] classesToCheck = {
                "de.robv.android.xposed.XposedHelpers",
                "de.robv.android.xposed.XposedBridge"
        };
        String[] methodsToCheck = { "findAndHookMethod", "hookAllMethods" };
        for (String className : classesToCheck) {
            try {
                Class<?> c = Class.forName(className);
                for (String methodName : methodsToCheck) {
                    for (Method m : c.getDeclaredMethods()) {
                        if (methodName.equals(m.getName())) {
                            if (details != null) {
                                details.add("Xposed API present: " + className + "." + methodName);
                            }
                            return true;
                        }
                    }
                }
            } catch (ClassNotFoundException ignored) {
                // 该类不存在，继续检查下一个
            } catch (Throwable t) {
                if (details != null) {
                    details.add("Reflection check exception: " + t.getMessage());
                }
                return true; // 反射异常可能为环境篡改
            }
        }
        return false;
    }

    /**
     * 检测可疑的 ClassLoader 实例（LSPosed InMemoryClassLoader、LspModuleClassLoader、XposedBridge）。
     * 需绕过 Hidden API 限制（VMDebug.getInstancesOfClasses）。
     */
    private static List<String> detectSuspiciousClassLoaders() {
        List<String> findings = new ArrayList<>();
        try {
            bypassHiddenApiRestrictions();
            Class<?> vmDebugClass = Class.forName("dalvik.system.VMDebug");
            Method getInstancesMethod = vmDebugClass.getDeclaredMethod(
                    "getInstancesOfClasses", Class[].class, boolean.class);
            getInstancesMethod.setAccessible(true);

            Class<?>[] classes = {ClassLoader.class};
            Object[][] instances = (Object[][]) getInstancesMethod.invoke(null, classes, false);

            if (instances == null || instances.length == 0) return findings;

            for (Object obj : instances[0]) {
                if (obj == null) continue;
                ClassLoader cl = (ClassLoader) obj;
                String clName = cl.getClass().getName();

                if (clName.contains("InMemoryClassLoader")
                        || clName.contains("LspModuleClassLoader")
                        || clName.contains("XposedBridge")
                        || clName.contains("EdXposed")) {
                    findings.add("Suspicious ClassLoader: " + clName);
                }

                try {
                    cl.loadClass("org.lsposed.lspd.core.Main");
                    findings.add("LSPosed core class loadable via: " + clName);
                } catch (ClassNotFoundException ignored) {
                    // 正常
                }

                ClassLoader parent = cl.getParent();
                while (parent != null) {
                    String parentName = parent.getClass().getName();
                    if (parentName.contains("Xposed") || parentName.contains("Lsp")) {
                        findings.add("Suspicious parent ClassLoader: " + parentName);
                        break;
                    }
                    parent = parent.getParent();
                }
            }
        } catch (Throwable ignored) {
            // Hidden API 限制或异常，返回空列表避免误报
        }
        return findings;
    }

    /** 绕过 Hidden API 限制以访问 VMDebug.getInstancesOfClasses */
    private static void bypassHiddenApiRestrictions() {
        try {
            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
            Method getRuntime = vmRuntimeClass.getDeclaredMethod("getRuntime");
            getRuntime.setAccessible(true);
            Object runtime = getRuntime.invoke(null);
            Method setHiddenApiExemptions = vmRuntimeClass.getDeclaredMethod(
                    "setHiddenApiExemptions", String[].class);
            setHiddenApiExemptions.setAccessible(true);
            setHiddenApiExemptions.invoke(runtime, new Object[]{new String[]{"L"}});
        } catch (Throwable ignored) {
            // 部分设备可能失败
        }
    }

    private static String readFileContent(String path) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }
}
