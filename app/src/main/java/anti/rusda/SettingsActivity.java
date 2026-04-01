package anti.rusda;

import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatDelegate;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.materialswitch.MaterialSwitch;

public class SettingsActivity extends BaseActivity {

    private static final String GITHUB_URL = "https://github.com/taisuii";
    private static final String KANXUE_URL = "https://bbs.kanxue.com/homepage-957122.htm";
    private static final String WECHAT_ID = "tais00";

    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        prefs = getSharedPreferences("sentry_prefs", MODE_PRIVATE);

        initViews();
    }

    private void initViews() {
        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        // Theme radio buttons
        findViewById(R.id.radio_theme_system).setOnClickListener(v -> applyTheme(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM));
        findViewById(R.id.radio_theme_light).setOnClickListener(v -> applyTheme(AppCompatDelegate.MODE_NIGHT_NO));
        findViewById(R.id.radio_theme_dark).setOnClickListener(v -> applyTheme(AppCompatDelegate.MODE_NIGHT_YES));

        // Set current theme selection
        int currentTheme = prefs.getInt("theme_mode", AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM);
        switch (currentTheme) {
            case AppCompatDelegate.MODE_NIGHT_NO:
                ((com.google.android.material.radiobutton.MaterialRadioButton) findViewById(R.id.radio_theme_light)).setChecked(true);
                break;
            case AppCompatDelegate.MODE_NIGHT_YES:
                ((com.google.android.material.radiobutton.MaterialRadioButton) findViewById(R.id.radio_theme_dark)).setChecked(true);
                break;
            default:
                ((com.google.android.material.radiobutton.MaterialRadioButton) findViewById(R.id.radio_theme_system)).setChecked(true);
                break;
        }

        // Language radio buttons - only English and Chinese
        findViewById(R.id.radio_lang_english).setOnClickListener(v -> setLanguage("en"));
        findViewById(R.id.radio_lang_chinese).setOnClickListener(v -> setLanguage("zh"));

        // Set current language selection (default is English)
        String currentLang = LocaleHelper.getLanguage(this);
        if ("zh".equals(currentLang)) {
            ((com.google.android.material.radiobutton.MaterialRadioButton) findViewById(R.id.radio_lang_chinese)).setChecked(true);
        } else {
            ((com.google.android.material.radiobutton.MaterialRadioButton) findViewById(R.id.radio_lang_english)).setChecked(true);
        }

        // Switches
        MaterialSwitch autoScanSwitch = findViewById(R.id.switch_auto_scan);
        autoScanSwitch.setChecked(prefs.getBoolean("auto_scan", false));
        autoScanSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            prefs.edit().putBoolean("auto_scan", isChecked).apply();
        });

        MaterialSwitch advancedChecksSwitch = findViewById(R.id.switch_advanced_checks);
        advancedChecksSwitch.setChecked(prefs.getBoolean("advanced_checks", false));
        advancedChecksSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            prefs.edit().putBoolean("advanced_checks", isChecked).apply();
        });

        // 设置版本号
        TextView versionText = findViewById(R.id.version_text);
        if (versionText != null) {
            String version = getString(R.string.version_prefix) + MainActivity.getVersionName();
            versionText.setText(version);
        }

        // Author info links
        setupAuthorLinks();
    }

    /**
     * 设置作者信息链接点击事件
     */
    private void setupAuthorLinks() {
        // GitHub
        LinearLayout githubContainer = findViewById(R.id.about_github_container);
        if (githubContainer != null) {
            githubContainer.setOnClickListener(v -> openLink(GITHUB_URL));
        }

        // WeChat - copy to clipboard
        LinearLayout wechatContainer = findViewById(R.id.wechat_container);
        if (wechatContainer != null) {
            wechatContainer.setOnClickListener(v -> copyWechatId());
        }

        // Kanxue Forum
        LinearLayout kanxueContainer = findViewById(R.id.about_kanxue_container);
        if (kanxueContainer != null) {
            kanxueContainer.setOnClickListener(v -> openLink(KANXUE_URL));
        }
    }

    /**
     * 打开链接
     */
    private void openLink(String url) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            startActivity(intent);
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, getString(R.string.no_browser_found), Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * 复制微信号到剪贴板
     */
    private void copyWechatId() {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            ClipData clip = ClipData.newPlainText("WeChat ID", WECHAT_ID);
            clipboard.setPrimaryClip(clip);
            Toast.makeText(this, getString(R.string.wechat_copied), Toast.LENGTH_SHORT).show();
        }
    }

    private void applyTheme(int mode) {
        AppCompatDelegate.setDefaultNightMode(mode);
        prefs.edit().putInt("theme_mode", mode).apply();
    }

    private void setLanguage(String lang) {
        LocaleHelper.setLocale(this, lang);
        // 切换语言后直接重启应用：避免 recreate 导致检测结果丢失、Native 状态异常无法检测
        Intent i = new Intent(this, MainActivity.class);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(i);
        finish();
    }
}
