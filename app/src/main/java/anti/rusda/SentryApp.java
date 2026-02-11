package anti.rusda;

import android.app.Application;
import android.content.Context;

public class SentryApp extends Application {

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(LocaleHelper.onAttach(base));
    }

    @Override
    public void onCreate() {
        super.onCreate();
    }
}
