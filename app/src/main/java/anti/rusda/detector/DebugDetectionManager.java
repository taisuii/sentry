package anti.rusda.detector;

import android.content.Context;
import android.os.Debug;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 调试相关检测：Frida、Xposed、IDA/ptrace 附加、端口等。
 * 依赖 libantidebug.so（端口扫描在 Native 层）。
 */
public class DebugDetectionManager {

    private static final String[] FRIDA_THREAD_KEYWORDS = {
            "gmain", "gdbus", "pool-spawner", "frida-agent", "frida-gadget",
            "frida", "gum-js-loop", "gthread", "gpool"
    };


    /** 端口扫描在 Native 层（syscall），结果由此方法返回 */
    private static native String[] nativeGetFridaPortScanResult();
    /** 内存签名扫描在 Native 层（syscall），防 Hook */
    private static native String[] nativeGetMemorySignatureResult();

    public static void ensureNativeLoaded() {
        try {
            System.loadLibrary("antidebug");
        } catch (Throwable ignored) { }
    }

    public List<DetectionResult> runAllDetections() {
        ensureNativeLoaded();
        List<DetectionResult> results = new ArrayList<>();
        results.add(detectFridaThreads());
        results.add(detectFridaPorts());
        results.add(detectMemorySignatures());
        results.add(detectNamedPipes());
        results.add(detectPtraceStatus());
        results.add(detectDebuggerAttached());
        results.add(checkLibraryIntegrity());
        return results;
    }

    private DetectionResult detectFridaThreads() {
        List<String> suspiciousThreads = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        try {
            File taskDir = new File("/proc/self/task");
            File[] threads = taskDir.listFiles();
            if (threads != null) {
                for (File thread : threads) {
                    File commFile = new File(thread, "comm");
                    if (commFile.exists()) {
                        String threadName = readFileContent(commFile.getAbsolutePath()).trim();
                        for (String keyword : FRIDA_THREAD_KEYWORDS) {
                            if (threadName.toLowerCase().contains(keyword)) {
                                suspiciousThreads.add("Thread " + thread.getName() + ": " + threadName);
                                status = DetectionResult.STATUS_DANGER;
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            suspiciousThreads.add("Error: " + e.getMessage());
        }
        DetectionResult result = new DetectionResult(
                "Frida Threads",
                status == DetectionResult.STATUS_NORMAL ? "No suspicious threads found" : suspiciousThreads.size() + " suspicious thread(s) detected",
                status
        );
        result.setDetails(suspiciousThreads);
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

    private DetectionResult checkLibraryIntegrity() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            details.add("Xposed framework detected");
            status = DetectionResult.STATUS_DANGER;
        } catch (ClassNotFoundException e) {
            details.add("Xposed framework not detected");
        }
        return new DetectionResult(
                "Xposed / Hook Framework",
                status == DetectionResult.STATUS_NORMAL ? "No Xposed detected" : "Framework modification detected",
                status,
                details
        );
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
