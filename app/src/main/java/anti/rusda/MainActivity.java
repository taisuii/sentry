package anti.rusda;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

import java.util.ArrayList;
import java.util.List;

import anti.rusda.detector.DebugDetectionManager;
import anti.rusda.detector.DetectionResult;
import anti.rusda.detector.EnvDetectionManager;
import anti.rusda.ui.MainPagerAdapter;


import java.security.MessageDigest;






public class MainActivity extends BaseActivity {
    /** 反调试分数权重：1.5x（分子/分母避免浮点误差） */
    private static final int DEBUG_SCORE_WEIGHT_NUMERATOR = 3;
    private static final int DEBUG_SCORE_WEIGHT_DENOMINATOR = 2;

    public static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] bytes = md.digest(input.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                int v = b & 0xFF;
                if (v < 16) sb.append('0');
                sb.append(Integer.toHexString(v));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
    static {
        System.loadLibrary("antidebug");
        try {
            System.loadLibrary("envdetect");
        } catch (Throwable ignored) { }
    }

    private androidx.viewpager2.widget.ViewPager2 pager;
    private TabLayout tabLayout;
    private MainPagerAdapter pagerAdapter;

    private OverviewFragment overviewFragment;
    private DebugFragment debugFragment;
    private EnvironmentFragment environmentFragment;

    private DebugDetectionManager debugDetectionManager;
    private EnvDetectionManager envDetectionManager;

    private List<DetectionResult> lastDebugResults = new ArrayList<>();
    private List<DetectionResult> lastEnvResults = new ArrayList<>();
    private int totalScore = -1;
    private int maxScore = -1;
    private boolean scanning = false;

    private final View.OnClickListener mScanClickListener = v -> runAllScans();

    /** 供 Fragment 在 onViewCreated 中获取并绑定到「开始检测」按钮 */
    public View.OnClickListener getScanClickListener() {
        return mScanClickListener;
    }

    /** 获取版本号（供其他组件使用） */
    public static String getVersionName() {
        return BuildConfig.VERSION_NAME;
    }

    /** 按冷却时间查询 GitHub 最新 Release，若有新版本则在概览页展示横幅 */
    private void scheduleGitHubVersionCheckIfDue(SharedPreferences prefs) {
        long last = prefs.getLong("last_github_release_check_ms", 0L);
        if (GitHubReleaseChecker.shouldSkipCheckDueToCooldown(last, GitHubReleaseChecker.defaultCooldownMs())) {
            return;
        }
        GitHubReleaseChecker.checkLatestAsync(result -> {
            prefs.edit().putLong("last_github_release_check_ms", System.currentTimeMillis()).apply();
            runOnUiThread(() -> {
                if (overviewFragment != null) {
                    overviewFragment.applyVersionCheckResult(result);
                }
            });
        });
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        debugDetectionManager = new DebugDetectionManager();
        envDetectionManager = new EnvDetectionManager(this);

        overviewFragment = new OverviewFragment();
        debugFragment = new DebugFragment();
        environmentFragment = new EnvironmentFragment();

        pager = findViewById(R.id.pager);
        pagerAdapter = new MainPagerAdapter(this, overviewFragment, debugFragment, environmentFragment);
        pager.setAdapter(pagerAdapter);
        pager.setOffscreenPageLimit(2);

        tabLayout = findViewById(R.id.tab_layout);
        new TabLayoutMediator(tabLayout, pager, (tab, position) -> {
            switch (position) {
                case 0:
                    tab.setText(R.string.tab_overview);
                    tab.setIcon(R.drawable.ic_home);
                    break;
                case 1:
                    tab.setText(R.string.tab_debug);
                    tab.setIcon(R.drawable.ic_scan);
                    break;
                case 2:
                    tab.setText(R.string.tab_environment);
                    tab.setIcon(R.drawable.ic_security);
                    break;
                default:
                    break;
            }
        }).attach();

        setupToolbar();
        applyNavigationBarInsets();

        SharedPreferences prefs = getSharedPreferences("sentry_prefs", MODE_PRIVATE);
        // 启动时自动检测：若用户已开启则延迟执行一次，确保 UI 就绪
        if (prefs.getBoolean("auto_scan", false)) {
            new Handler(Looper.getMainLooper()).postDelayed(this::runAllScans, 500);
        }

        scheduleGitHubVersionCheckIfDue(prefs);

        Log.d("SentryTag", "MainActivity    md5: " + md5("1234567890"));
    }

    /** 为底部 Tab 预留系统导航条（Home 条/手势条）区域，避免被遮挡 */
    private void applyNavigationBarInsets() {
        View root = findViewById(android.R.id.content);
        int tabBarHeightPx = (int) (56 * getResources().getDisplayMetrics().density);

        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            int bottomInset = insets.getInsets(WindowInsetsCompat.Type.navigationBars()).bottom;
            androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams tabLp =
                    (androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams) tabLayout.getLayoutParams();
            tabLp.bottomMargin = bottomInset;
            tabLayout.setLayoutParams(tabLp);

            androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams pagerLp =
                    (androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams) pager.getLayoutParams();
            pagerLp.bottomMargin = tabBarHeightPx + bottomInset;
            pager.setLayoutParams(pagerLp);

            return insets;
        });
        ViewCompat.requestApplyInsets(root);
    }

    private void setupToolbar() {
        com.google.android.material.appbar.MaterialToolbar toolbar = findViewById(R.id.toolbar);

        // 设置标题（不带版本号）
        toolbar.setTitle(R.string.app_name);

        // 创建带版本号的副标题
        String subtitle = getString(R.string.version_prefix) + BuildConfig.VERSION_NAME;
        toolbar.setSubtitle(subtitle);

        toolbar.setOnMenuItemClickListener(item -> {
            if (item.getItemId() == R.id.action_settings) {
                startActivityForResult(new Intent(this, SettingsActivity.class), 100);
                return true;
            }
            return false;
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 100 && resultCode == RESULT_OK) {
            Intent intent = new Intent(this, MainActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
            finish();
            startActivity(intent);
        }
    }

    private void runAllScans() {
        if (scanning) return;
        scanning = true;
        setScanningUi(true);

        new Thread(() -> {
            try {
                List<DetectionResult> debug = debugDetectionManager.runAllDetections(getApplicationContext());
                List<DetectionResult> env = envDetectionManager.runAllDetections();

                int total = 0, max = 0;
                for (DetectionResult r : debug) {
                    total += applyDebugScoreWeight(r.getEarnedScore());
                    max += applyDebugScoreWeight(r.getMaxScore());
                }
                for (DetectionResult r : env) {
                    total += r.getEarnedScore();
                    max += r.getMaxScore();
                }

                lastDebugResults = debug;
                lastEnvResults = env;
                totalScore = total;
                maxScore = max;
            } catch (Throwable t) {
                lastDebugResults = new ArrayList<>();
                lastEnvResults = new ArrayList<>();
                totalScore = -1;
                maxScore = -1;
            }
            runOnUiThread(() -> {
                scanning = false;
                setScanningUi(false);
                overviewFragment.setScore(totalScore, maxScore);
                overviewFragment.setWarningAndAnomalyTags(collectWarningAndAnomalyTags());
                debugFragment.setResults(lastDebugResults);
                environmentFragment.setResults(lastEnvResults);
            });
        }).start();
    }

    private List<DetectionResult> collectWarningAndAnomalyTags() {
        List<DetectionResult> list = new ArrayList<>();
        for (DetectionResult r : lastDebugResults) {
            if (r.getStatus() != DetectionResult.STATUS_NORMAL) {
                list.add(r);
            }
        }
        for (DetectionResult r : lastEnvResults) {
            if (r.getStatus() != DetectionResult.STATUS_NORMAL) {
                list.add(r);
            }
        }
        return list;
    }

    private void setScanningUi(boolean scanning) {
        overviewFragment.setScanning(scanning);
        debugFragment.setScanning(scanning);
        environmentFragment.setScanning(scanning);
    }

    /** 对反调试检测分数应用 1.5x 权重，并做四舍五入。 */
    private static int applyDebugScoreWeight(int score) {
        return (score * DEBUG_SCORE_WEIGHT_NUMERATOR + (DEBUG_SCORE_WEIGHT_DENOMINATOR / 2))
                / DEBUG_SCORE_WEIGHT_DENOMINATOR;
    }
}
