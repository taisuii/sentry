package anti.rusda.detector;

import android.os.Build;
import android.os.SystemClock;

import java.util.HashMap;
import java.util.Map;

/**
 * 设备指纹采集器，供后续服务端行为分析、设备碰撞检测使用。
 * 采集 Build.FINGERPRINT、elapsedRealtime、/proc/version 等。
 * 本次仅做接口与采集逻辑，不做服务端对接。
 */
public class DeviceFingerprintCollector {

    static {
        try {
            System.loadLibrary("envdetect");
        } catch (Throwable ignored) { }
    }

    private static native String nativeGetProcVersion();

    /**
     * 采集设备指纹数据。
     * @return 键值对，包含 fingerprint、elapsedRealtime、procVersion 等
     */
    public static Map<String, String> collect() {
        Map<String, String> data = new HashMap<>();
        data.put("fingerprint", Build.FINGERPRINT != null ? Build.FINGERPRINT : "");
        data.put("elapsedRealtime", String.valueOf(SystemClock.elapsedRealtime()));
        String procVer = nativeGetProcVersion();
        data.put("procVersion", procVer != null ? procVer : "");
        return data;
    }
}
