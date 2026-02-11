package anti.rusda;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

/**
 * BaseActivity - 提供统一的语言切换支持
 * 所有Activity继承此类即可自动响应语言切换
 */
public abstract class BaseActivity extends AppCompatActivity {

    private static final String ACTION_LANGUAGE_CHANGED = "anti.rusda.LANGUAGE_CHANGED";
    private BroadcastReceiver languageReceiver;
    private String currentLanguage;

    @Override
    protected void attachBaseContext(Context newBase) {
        super.attachBaseContext(LocaleHelper.onAttach(newBase));
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        currentLanguage = LocaleHelper.getLanguage(this);
        registerLanguageReceiver();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterLanguageReceiver();
    }

    @Override
    protected void onResume() {
        super.onResume();
        // 检查语言是否在其他地方被修改
        String newLanguage = LocaleHelper.getLanguage(this);
        if (!newLanguage.equals(currentLanguage)) {
            currentLanguage = newLanguage;
            recreate();
        }
    }

    private void registerLanguageReceiver() {
        languageReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (ACTION_LANGUAGE_CHANGED.equals(intent.getAction())) {
                    currentLanguage = LocaleHelper.getLanguage(BaseActivity.this);
                    recreate();
                }
            }
        };
        LocalBroadcastManager.getInstance(this)
                .registerReceiver(languageReceiver, new IntentFilter(ACTION_LANGUAGE_CHANGED));
    }

    private void unregisterLanguageReceiver() {
        if (languageReceiver != null) {
            LocalBroadcastManager.getInstance(this).unregisterReceiver(languageReceiver);
        }
    }

    /**
     * 通知所有Activity语言已变更
     */
    public static void notifyLanguageChanged(Context context) {
        Intent intent = new Intent(ACTION_LANGUAGE_CHANGED);
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
    }
}
