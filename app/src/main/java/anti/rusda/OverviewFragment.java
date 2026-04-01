package anti.rusda;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.google.android.material.card.MaterialCardView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import anti.rusda.R;
import anti.rusda.detector.DetectionResult;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;

public class OverviewFragment extends Fragment {

    private static final String PREFS = "sentry_prefs";
    private static final String PREF_PENDING_UPDATE_VERSION = "pending_update_remote_version";
    private static final String PREF_PENDING_UPDATE_URL = "pending_update_release_url";
    private static final String PREF_DISMISSED_UPDATE_VERSION = "dismissed_update_version";

    private static final String GITHUB_URL = "https://github.com/taisuii";

    private TextView scoreValue;
    private TextView scoreLabel;
    private MaterialButton scanButton;
    private LinearLayout scanProgressContainer;
    private LinearProgressIndicator scanProgress;
    private LinearLayout deviceInfoContainer;
    private TextView warningTagsLabel;
    private ChipGroup warningTagsContainer;
    private ImageView githubIcon;
    private MaterialCardView updateBanner;
    private TextView updateBannerMessage;
    private MaterialButton updateBannerOpen;
    private MaterialButton updateBannerDismiss;

    private String pendingReleaseUrl;

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
        warningTagsLabel = view.findViewById(R.id.warning_tags_label);
        warningTagsContainer = view.findViewById(R.id.warning_tags_container);
        githubIcon = view.findViewById(R.id.github_icon);
        updateBanner = view.findViewById(R.id.update_banner);
        updateBannerMessage = view.findViewById(R.id.update_banner_message);
        updateBannerOpen = view.findViewById(R.id.update_banner_open);
        updateBannerDismiss = view.findViewById(R.id.update_banner_dismiss);

        // 设置 GitHub 图标点击事件
        if (githubIcon != null) {
            githubIcon.setOnClickListener(v -> openGitHub());
        }

        if (updateBannerOpen != null) {
            updateBannerOpen.setOnClickListener(v -> openPendingRelease());
        }
        if (updateBannerDismiss != null) {
            updateBannerDismiss.setOnClickListener(v -> dismissUpdateBannerForCurrentPending());
        }

        fillDeviceInfo();
        refreshScoreDisplay();
        bindScanButton();
        applyStoredUpdateHint();
    }

    /**
     * 展示或隐藏「新版本」横幅（来自 GitHub Release）。主线程调用。
     */
    public void applyVersionCheckResult(@NonNull GitHubReleaseChecker.Result result) {
        SharedPreferences prefs = prefs();
        if (result.success && result.updateAvailable
                && result.remoteVersionName != null
                && result.releasePageUrl != null) {
            prefs.edit()
                    .putString(PREF_PENDING_UPDATE_VERSION, result.remoteVersionName)
                    .putString(PREF_PENDING_UPDATE_URL, result.releasePageUrl)
                    .apply();
            showUpdateBannerIfNotDismissed(result.remoteVersionName, result.releasePageUrl);
            return;
        }
        if (result.success && !result.updateAvailable) {
            prefs.edit()
                    .remove(PREF_PENDING_UPDATE_VERSION)
                    .remove(PREF_PENDING_UPDATE_URL)
                    .apply();
            hideUpdateBanner();
            return;
        }
        // 网络失败等：保留已缓存的待更新状态，仅刷新当前是否仍应显示
        applyStoredUpdateHint();
    }

    /** 从本地缓存恢复横幅（冷却期内未请求网络时仍可提示） */
    private void applyStoredUpdateHint() {
        SharedPreferences prefs = prefs();
        String remote = prefs.getString(PREF_PENDING_UPDATE_VERSION, null);
        String url = prefs.getString(PREF_PENDING_UPDATE_URL, null);
        if (remote == null || url == null || remote.isEmpty() || url.isEmpty()) {
            hideUpdateBanner();
            return;
        }
        String local = BuildConfig.VERSION_NAME != null ? BuildConfig.VERSION_NAME.trim() : "";
        if (GitHubReleaseChecker.compareSemanticVersions(
                GitHubReleaseChecker.normalizeVersionTag(remote), local) <= 0) {
            hideUpdateBanner();
            return;
        }
        showUpdateBannerIfNotDismissed(remote, url);
    }

    private void showUpdateBannerIfNotDismissed(@NonNull String remoteVersion, @NonNull String releaseUrl) {
        if (updateBanner == null || updateBannerMessage == null || getContext() == null) {
            return;
        }
        String dismissed = prefs().getString(PREF_DISMISSED_UPDATE_VERSION, "");
        if (remoteVersion.equals(dismissed)) {
            updateBanner.setVisibility(View.GONE);
            return;
        }
        pendingReleaseUrl = releaseUrl;
        String local = BuildConfig.VERSION_NAME != null ? BuildConfig.VERSION_NAME : "";
        updateBannerMessage.setText(getString(R.string.update_available_message, remoteVersion, local));
        updateBanner.setVisibility(View.VISIBLE);
    }

    private void hideUpdateBanner() {
        pendingReleaseUrl = null;
        if (updateBanner != null) {
            updateBanner.setVisibility(View.GONE);
        }
    }

    private void openPendingRelease() {
        if (pendingReleaseUrl == null || getContext() == null) {
            return;
        }
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(pendingReleaseUrl)));
        } catch (ActivityNotFoundException e) {
            Toast.makeText(requireContext(), getString(R.string.no_browser_found), Toast.LENGTH_SHORT).show();
        }
    }

    private void dismissUpdateBannerForCurrentPending() {
        SharedPreferences prefs = prefs();
        String remote = prefs.getString(PREF_PENDING_UPDATE_VERSION, null);
        if (remote != null) {
            prefs.edit().putString(PREF_DISMISSED_UPDATE_VERSION, remote).apply();
        }
        hideUpdateBanner();
    }

    private SharedPreferences prefs() {
        return requireContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /**
     * 打开 GitHub 主页
     */
    private void openGitHub() {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(GITHUB_URL));
            startActivity(intent);
        } catch (ActivityNotFoundException e) {
            Toast.makeText(requireContext(),
                getString(R.string.no_browser_found),
                Toast.LENGTH_SHORT).show();
        }
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

    /** 设置警告与异常项标签（概览页展示：橙色=警告，红色=异常） */
    public void setWarningAndAnomalyTags(List<DetectionResult> items) {
        if (warningTagsLabel == null || warningTagsContainer == null) return;
        boolean hasContent = items != null && !items.isEmpty();
        warningTagsLabel.setVisibility(hasContent ? View.VISIBLE : View.GONE);
        warningTagsContainer.setVisibility(hasContent ? View.VISIBLE : View.GONE);
        if (!hasContent) return;

        warningTagsContainer.removeAllViews();
        for (DetectionResult r : items) {
            Chip chip = new Chip(requireContext());
            chip.setText(r.getTitle());
            boolean isDanger = r.getStatus() == DetectionResult.STATUS_DANGER;
            chip.setChipBackgroundColor(ContextCompat.getColorStateList(requireContext(),
                    isDanger ? R.color.status_danger_container : R.color.status_warning_container));
            chip.setTextColor(ContextCompat.getColor(requireContext(),
                    isDanger ? R.color.status_danger : R.color.status_warning));
            chip.setChipMinHeight((int) (32 * getResources().getDisplayMetrics().density));
            chip.setChipStrokeWidth(0);
            warningTagsContainer.addView(chip);
        }
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
