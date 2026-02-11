package anti.rusda;

import android.content.SharedPreferences;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatDelegate;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.materialswitch.MaterialSwitch;

public class SettingsActivity extends BaseActivity {

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
    }

    private void applyTheme(int mode) {
        AppCompatDelegate.setDefaultNightMode(mode);
        prefs.edit().putInt("theme_mode", mode).apply();
    }

    private void setLanguage(String lang) {
        LocaleHelper.setLocale(this, lang);
        // 优雅方式：广播通知所有Activity语言已变更
        notifyLanguageChanged(this);
        // 本界面也会收到广播并自动重建
    }
}
