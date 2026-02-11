package anti.rusda.detector;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Debug;
import android.os.Process;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class DetectionManager {

    private Context context;

    private static final String[] FRIDA_THREAD_KEYWORDS = {
            "gmain", "gdbus", "pool-spawner", "frida-agent", "frida-gadget",
            "frida", "gum-js-loop", "gthread", "gpool"
    };

    private static final String[] FRIDA_MEMORY_SIGNATURES = {
            "frida", "FRIDA", "gum-js", "gthread", "gobject"
    };

    private static final int[] FRIDA_PORTS = {27042, 27043, 27044};

    private static final String[] SUSPICIOUS_PATHS = {
            "/data/local/tmp/frida",
            "/data/local/tmp/frida-server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server",
            "/data/app/frida",
            "/debug_ramdisk"
    };

    public DetectionManager() {
    }

    public DetectionManager(Context context) {
        this.context = context;
    }

    public List<DetectionResult> runAllDetections() {
        List<DetectionResult> results = new ArrayList<>();

        // 1. Thread Detection
        results.add(detectFridaThreads());

        // 2. Port Scanning
        results.add(detectFridaPorts());

        // 3. Memory Signature Detection
        results.add(detectMemorySignatures());

        // 4. Named Pipe Detection
        results.add(detectNamedPipes());

        // 5. Debug Mode Detection
        results.add(detectDebugMode());

        // 6. Root Detection
        results.add(detectRoot());

        // 7. File System Detection
        results.add(detectSuspiciousFiles());

        // 8. Ptrace Status Detection
        results.add(detectPtraceStatus());

        // 9. Emulator Detection
        results.add(detectEmulator());

        // 10. SELinux Status
        results.add(detectSELinuxStatus());

        // 11. Library Integrity Check
        results.add(checkLibraryIntegrity());

        // 12. Process Status Check
        results.add(checkProcessStatus());

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
                "Detected Frida Threads",
                status == DetectionResult.STATUS_NORMAL ? "No suspicious threads found" : suspiciousThreads.size() + " suspicious thread(s) detected",
                status
        );
        result.setDetails(suspiciousThreads);
        return result;
    }

    private DetectionResult detectFridaPorts() {
        List<String> openPorts = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        for (int port : FRIDA_PORTS) {
            try {
                Socket socket = new Socket("127.0.0.1", port);
                socket.close();
                openPorts.add("Port " + port + " is open (Frida default)");
                status = DetectionResult.STATUS_DANGER;
            } catch (IOException e) {
                // Port is closed, which is good
            }
        }

        DetectionResult result = new DetectionResult(
                "Port Scanning",
                openPorts.isEmpty() ? "No Frida ports detected" : openPorts.size() + " Frida port(s) detected",
                status
        );
        result.setDetails(openPorts.isEmpty() ?
                java.util.Collections.singletonList("All Frida default ports are closed") : openPorts);
        return result;
    }

    private DetectionResult detectMemorySignatures() {
        List<String> findings = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        try {
            String mapsContent = readFileContent("/proc/self/maps");
            String[] lines = mapsContent.split("\\n");

            for (String line : lines) {
                for (String signature : FRIDA_MEMORY_SIGNATURES) {
                    if (line.toLowerCase().contains(signature)) {
                        findings.add("Found '" + signature + "' in: " + line.trim());
                        status = DetectionResult.STATUS_DANGER;
                    }
                }
            }
        } catch (Exception e) {
            findings.add("Error reading memory maps: " + e.getMessage());
        }

        DetectionResult result = new DetectionResult(
                "Memory Signature Detection",
                findings.isEmpty() ? "No Frida signatures in memory" : findings.size() + " signature(s) found",
                status
        );
        result.setDetails(findings.isEmpty() ?
                java.util.Collections.singletonList("Memory scan completed - clean") : findings);
        return result;
    }

    private DetectionResult detectNamedPipes() {
        List<String> pipes = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        try {
            String unixContent = readFileContent("/proc/self/net/unix");
            String[] lines = unixContent.split("\\n");

            for (String line : lines) {
                if (line.toLowerCase().contains("frida") ||
                        line.toLowerCase().contains("gmain") ||
                        line.toLowerCase().contains("gdbus")) {
                    pipes.add(line.trim());
                    status = DetectionResult.STATUS_DANGER;
                }
            }
        } catch (Exception e) {
            pipes.add("Error checking pipes: " + e.getMessage());
        }

        DetectionResult result = new DetectionResult(
                "Named Pipe Detection",
                pipes.isEmpty() ? "No suspicious pipes detected" : pipes.size() + " suspicious pipe(s) detected",
                status
        );
        result.setDetails(pipes.isEmpty() ?
                java.util.Collections.singletonList("No Frida-related named pipes found") : pipes);
        return result;
    }

    private DetectionResult detectDebugMode() {
        boolean isDebug = Debug.isDebuggerConnected();

        List<String> details = new ArrayList<>();
        if (isDebug) {
            details.add("Debugger is currently connected");
        } else {
            details.add("No debugger detected");
        }

        // Check if app is debuggable
        if (context != null) {
            try {
                ApplicationInfo appInfo = context.getApplicationInfo();
                boolean isDebuggable = (appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;

                if (isDebuggable) {
                    details.add("App is marked as debuggable");
                }
            } catch (Exception e) {
                details.add("Could not check debuggable flag");
            }
        }

        int status = isDebug ? DetectionResult.STATUS_WARNING : DetectionResult.STATUS_NORMAL;

        return new DetectionResult(
                "Debug Mode Detection",
                status == DetectionResult.STATUS_NORMAL ? "No debugger detected" : "Debugger detected",
                status,
                details
        );
    }

    private DetectionResult detectRoot() {
        List<String> indicators = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        String[] rootIndicators = {
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/su/bin/su",
                "/magisk/.core/bin/su",
                "/system/sbin/su"
        };

        for (String path : rootIndicators) {
            if (new File(path).exists()) {
                indicators.add("Found: " + path);
                status = DetectionResult.STATUS_WARNING;
            }
        }

        // Check for Magisk
        if (new File("/data/adb/magisk").exists()) {
            indicators.add("Magisk directory detected");
            status = DetectionResult.STATUS_WARNING;
        }

        DetectionResult result = new DetectionResult(
                "Root Detection",
                indicators.isEmpty() ? "Device appears unrooted" : indicators.size() + " root indicator(s) found",
                status
        );
        result.setDetails(indicators.isEmpty() ?
                java.util.Collections.singletonList("No root binaries or Magisk detected") : indicators);
        return result;
    }

    private DetectionResult detectSuspiciousFiles() {
        List<String> findings = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        for (String path : SUSPICIOUS_PATHS) {
            if (new File(path).exists()) {
                findings.add("Found: " + path);
                status = DetectionResult.STATUS_DANGER;
            }
        }

        DetectionResult result = new DetectionResult(
                "Suspicious Files Detection",
                findings.isEmpty() ? "No suspicious files detected" : findings.size() + " suspicious file(s) detected",
                status
        );
        result.setDetails(findings.isEmpty() ?
                java.util.Collections.singletonList("No Frida-related files found") : findings);
        return result;
    }

    private DetectionResult detectPtraceStatus() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        try {
            String statusContent = readFileContent("/proc/self/status");
            String[] lines = statusContent.split("\\n");

            for (String line : lines) {
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
                "Ptrace Status",
                status == DetectionResult.STATUS_NORMAL ? "Process is not being traced" : "Process is being traced!",
                status,
                details
        );
    }

    private DetectionResult detectEmulator() {
        List<String> indicators = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        // Check hardware properties
        String[] emulatorIndicators = {
                "generic",
                "unknown",
                "google_sdk",
                "sdk",
                "sdk_x86",
                "vbox86p",
                "emulator",
                "simulator",
                "ranchu",
                "goldfish"
        };

        String hardware = Build.HARDWARE.toLowerCase();
        String product = Build.PRODUCT.toLowerCase();
        String device = Build.DEVICE.toLowerCase();
        String brand = Build.BRAND.toLowerCase();

        for (String indicator : emulatorIndicators) {
            if (hardware.contains(indicator) || product.contains(indicator) ||
                    device.contains(indicator) || brand.contains(indicator)) {
                indicators.add("Indicator found in build info: " + indicator);
                status = DetectionResult.STATUS_WARNING;
            }
        }

        // Check for emulator-specific files
        String[] emulatorFiles = {
                "/dev/socket/qemud",
                "/dev/qemu_pipe",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace",
                "/system/bin/qemu-props"
        };

        for (String file : emulatorFiles) {
            if (new File(file).exists()) {
                indicators.add("Emulator file found: " + file);
                status = DetectionResult.STATUS_WARNING;
            }
        }

        // Check for BlueStacks, Nox, etc.
        if (new File("/data/misc/emu/update_check.cfg").exists()) {
            indicators.add("BlueStacks configuration detected");
            status = DetectionResult.STATUS_WARNING;
        }

        DetectionResult result = new DetectionResult(
                "Emulator Detection",
                indicators.isEmpty() ? "Running on physical device" : indicators.size() + " emulator indicator(s) found",
                status
        );
        result.setDetails(indicators.isEmpty() ?
                java.util.Collections.singletonList("Device appears to be a physical device") : indicators);
        return result;
    }

    private DetectionResult detectSELinuxStatus() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        try {
            String selinuxContent = readFileContent("/sys/fs/selinux/enforce");
            int enforceMode = Integer.parseInt(selinuxContent.trim());

            if (enforceMode == 0) {
                details.add("SELinux is in permissive mode");
                status = DetectionResult.STATUS_WARNING;
            } else {
                details.add("SELinux is enforcing");
            }
        } catch (Exception e) {
            // SELinux file might not exist on some devices
            details.add("Could not determine SELinux status: " + e.getMessage());
        }

        return new DetectionResult(
                "SELinux Status",
                status == DetectionResult.STATUS_NORMAL ? "SELinux is enforcing" : "SELinux is permissive",
                status,
                details
        );
    }

    private DetectionResult checkLibraryIntegrity() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        // Check for common hooked libraries
        String[] criticalLibs = {
                "/system/lib/libc.so",
                "/system/lib64/libc.so",
                "/system/bin/linker",
                "/system/bin/linker64"
        };

        for (String lib : criticalLibs) {
            File file = new File(lib);
            if (file.exists()) {
                details.add("Library exists: " + lib);
            }
        }

        // Check for Xposed
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            details.add("Xposed framework detected");
            status = DetectionResult.STATUS_DANGER;
        } catch (ClassNotFoundException e) {
            details.add("Xposed framework not detected");
        }

        return new DetectionResult(
                "Library Integrity",
                status == DetectionResult.STATUS_NORMAL ? "Libraries appear intact" : "Framework modification detected",
                status,
                details
        );
    }

    private DetectionResult checkProcessStatus() {
        List<String> details = new ArrayList<>();
        int status = DetectionResult.STATUS_NORMAL;

        try {
            // Get current PID
            int pid = Process.myPid();
            details.add("Process ID: " + pid);

            // Check process name
            if (context != null) {
                String packageName = context.getPackageName();
                details.add("Package name: " + packageName);

                // Check for multi-instance indicators in package name
                if (packageName != null && (packageName.contains(":") || packageName.toLowerCase().contains("dual"))) {
                    details.add("Package name suggests dual app");
                    status = DetectionResult.STATUS_WARNING;
                }

                // Check data directory
                if (context.getFilesDir() != null) {
                    String dataDir = context.getFilesDir().getAbsolutePath();
                    details.add("Files directory: " + dataDir);

                    if (dataDir.contains("parallel") || dataDir.contains("dual") ||
                            dataDir.contains("clone") || dataDir.contains("multi")) {
                        details.add("Suspicious data directory path detected");
                        status = DetectionResult.STATUS_WARNING;
                    }
                }
            }

        } catch (Exception e) {
            details.add("Error checking process status: " + e.getMessage());
        }

        return new DetectionResult(
                "Multi-instance Detection",
                status == DetectionResult.STATUS_NORMAL ? "No multi-instance detected" : "Multi-instance app detected",
                status,
                details
        );
    }

    private String readFileContent(String path) throws IOException {
        StringBuilder content = new StringBuilder();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(path));
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
        return content.toString();
    }
}
