package anti.rusda;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
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

public class MainActivity extends BaseActivity {

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

        // 启动时自动检测：若用户已开启则延迟执行一次，确保 UI 就绪
        SharedPreferences prefs = getSharedPreferences("sentry_prefs", MODE_PRIVATE);
        if (prefs.getBoolean("auto_scan", false)) {
            new Handler(Looper.getMainLooper()).postDelayed(this::runAllScans, 500);
        }
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
                    total += r.getEarnedScore();
                    max += r.getMaxScore();
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
                debugFragment.setResults(lastDebugResults);
                environmentFragment.setResults(lastEnvResults);
            });
        }).start();
    }

    private void setScanningUi(boolean scanning) {
        overviewFragment.setScanning(scanning);
        debugFragment.setScanning(scanning);
        environmentFragment.setScanning(scanning);
    }
}
