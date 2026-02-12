package anti.rusda;

import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import anti.rusda.R;

public class OverviewFragment extends Fragment {

    private TextView scoreValue;
    private TextView scoreLabel;
    private MaterialButton scanButton;
    private LinearLayout scanProgressContainer;
    private LinearProgressIndicator scanProgress;
    private LinearLayout deviceInfoContainer;

    private int totalScore = -1;
    private int maxScore = -1;

    private static final ExecutorService kernelExecutor = Executors.newSingleThreadExecutor();

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_overview, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        scoreValue = view.findViewById(R.id.score_value);
        scoreLabel = view.findViewById(R.id.score_label);
        scanButton = view.findViewById(R.id.scan_button);
        scanProgressContainer = view.findViewById(R.id.scan_progress_container);
        scanProgress = view.findViewById(R.id.scan_progress);
        deviceInfoContainer = view.findViewById(R.id.device_info_container);
        fillDeviceInfo();
        refreshScoreDisplay();
        bindScanButton();
    }

    @Override
    public void onResume() {
        super.onResume();
        // 语言/主题切换后 Activity 会 recreate，需在 onResume 重新绑定确保点击有效
        bindScanButton();
    }

    private void bindScanButton() {
        if (scanButton != null && getActivity() instanceof MainActivity) {
            scanButton.setOnClickListener(((MainActivity) getActivity()).getScanClickListener());
        }
    }

    public void setScore(int total, int max) {
        this.totalScore = total;
        this.maxScore = max;
        refreshScoreDisplay();
    }

    public void setScanning(boolean scanning) {
        if (scanButton != null) scanButton.setEnabled(!scanning);
        if (scanProgressContainer != null) scanProgressContainer.setVisibility(scanning ? View.VISIBLE : View.GONE);
    }

    private void refreshScoreDisplay() {
        if (scoreValue == null) return;
        if (maxScore <= 0 || totalScore < 0) {
            scoreValue.setText("—");
            return;
        }
        int percent = (int) Math.round(100.0 * totalScore / maxScore);
        scoreValue.setText(String.valueOf(percent));
    }

    private void fillDeviceInfo() {
        if (deviceInfoContainer == null) return;
        deviceInfoContainer.removeAllViews();
        int pad = (int) (12 * getResources().getDisplayMetrics().density);

        // Device: Model, Manufacturer, Device, Brand
        addInfoRow(getString(R.string.label_model), Build.MODEL != null ? Build.MODEL : "—", pad);
        addInfoRow(getString(R.string.label_manufacturer), Build.MANUFACTURER != null ? Build.MANUFACTURER : "—", pad);
        addInfoRow(getString(R.string.label_device), Build.DEVICE != null ? Build.DEVICE : "—", pad);
        addInfoRow(getString(R.string.label_brand), Build.BRAND != null ? Build.BRAND : "—", pad);

        // Android Version: e.g. "16 (API 36)"
        String androidVer = Build.VERSION.RELEASE != null
                ? Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")"
                : String.valueOf(Build.VERSION.SDK_INT);
        addInfoRow(getString(R.string.label_android_version), androidVer, pad);

        // Security Patch
        String securityPatch = Build.VERSION.SECURITY_PATCH != null ? Build.VERSION.SECURITY_PATCH : "—";
        addInfoRow(getString(R.string.label_security_patch), securityPatch, pad);

        // Kernel (from /proc/version) - 异步加载，避免主线程 I/O 或权限导致不显示
        TextView kernelRow = addInfoRow(getString(R.string.label_kernel), "…", pad);
        loadKernelVersionAsync(kernelRow);

        // Build Type & Build Tags
        addInfoRow(getString(R.string.label_build_type), Build.TYPE != null ? Build.TYPE : "—", pad);
        addInfoRow(getString(R.string.label_build_tags), Build.TAGS != null ? Build.TAGS : "—", pad);

        // Fingerprint (may be long, allow wrap)
        String fingerprint = Build.FINGERPRINT != null ? Build.FINGERPRINT : "—";
        addInfoRow(getString(R.string.label_fingerprint), fingerprint, pad);
    }

    /** 添加一行设备信息，返回该行 TextView 便于后续更新（如内核版本） */
    private TextView addInfoRow(String label, String value, int verticalPad) {
        TextView row = new TextView(requireContext());
        row.setTag(label);
        row.setText(label + ": " + value);
        row.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium);
        row.setPadding(0, verticalPad / 2, 0, verticalPad / 2);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        row.setLayoutParams(lp);
        deviceInfoContainer.addView(row);
        return row;
    }

    private void loadKernelVersionAsync(TextView kernelRow) {
        if (kernelRow == null || getContext() == null) return;
        String label = getString(R.string.label_kernel);
        kernelExecutor.execute(() -> {
            String version = readKernelVersion();
            if (getActivity() != null) {
                getActivity().runOnUiThread(() -> {
                    if (kernelRow.getTag() != null) {
                        kernelRow.setText(label + ": " + version);
                    }
                });
            }
        });
    }

    private String readKernelVersion() {
        // 优先读 /proc/version（完整信息）；部分设备（如 Android 16+ 或厂商限制）可能不可读
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream("/proc/version"), StandardCharsets.UTF_8))) {
            String line = r.readLine();
            if (line != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) return trimmed;
            }
        } catch (Throwable ignored) {
            // 忽略，尝试备用方式
        }
        // 备用：系统属性，无需文件读权限，多数设备可用
        String osVersion = System.getProperty("os.version");
        if (osVersion != null && !osVersion.isEmpty()) return osVersion;
        return "—";
    }
}
