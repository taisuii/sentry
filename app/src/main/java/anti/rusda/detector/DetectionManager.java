package anti.rusda.detector;

import android.content.Context;

import java.util.ArrayList;
import java.util.List;

/**
 * 兼容入口：合并调试检测与环境检测，返回全部检测项。
 * 实际实现已拆分至 {@link DebugDetectionManager} 与 {@link EnvDetectionManager}。
 */
public class DetectionManager {

    private final Context context;

    public DetectionManager() {
        this.context = null;
    }

    public DetectionManager(Context context) {
        this.context = context;
    }

    public List<DetectionResult> runAllDetections() {
        List<DetectionResult> results = new ArrayList<>();
        DebugDetectionManager.ensureNativeLoaded();
        DebugDetectionManager debug = new DebugDetectionManager();
        results.addAll(debug.runAllDetections(context));
        EnvDetectionManager env = new EnvDetectionManager(context != null ? context : null);
        if (context != null) {
            results.addAll(env.runAllDetections());
        }
        return results;
    }
}
