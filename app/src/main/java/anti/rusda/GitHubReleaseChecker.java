package anti.rusda;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * 从 GitHub Releases 获取最新版本并与本地 {@link BuildConfig#VERSION_NAME} 比较。
 * Release 的 tag_name 建议使用语义版本（如 1.0.1 或 v1.0.1），与 gradle 中 versionName 对齐。
 */
public final class GitHubReleaseChecker {

    private static final String API_LATEST =
            "https://api.github.com/repos/taisuii/sentry/releases/latest";
    private static final String USER_AGENT = "Sentry-Android/" + BuildConfig.VERSION_NAME;
    private static final int CONNECT_TIMEOUT_MS = 12_000;
    private static final int READ_TIMEOUT_MS = 12_000;

    private GitHubReleaseChecker() {
    }

    public interface Callback {
        void onResult(@NonNull Result result);
    }

    /** 拉取结果：成功时可读取 remoteVersionName、releasePageUrl；失败时 errorMessage 非空 */
    public static final class Result {
        public final boolean success;
        @Nullable
        public final String remoteVersionName;
        @Nullable
        public final String releasePageUrl;
        public final boolean updateAvailable;
        @Nullable
        public final String errorMessage;

        Result(boolean success, @Nullable String remoteVersionName, @Nullable String releasePageUrl,
                boolean updateAvailable, @Nullable String errorMessage) {
            this.success = success;
            this.remoteVersionName = remoteVersionName;
            this.releasePageUrl = releasePageUrl;
            this.updateAvailable = updateAvailable;
            this.errorMessage = errorMessage;
        }

        static Result failure(@NonNull String message) {
            return new Result(false, null, null, false, message);
        }

        static Result upToDate(@Nullable String remote, @Nullable String url) {
            return new Result(true, remote, url, false, null);
        }

        static Result hasUpdate(@NonNull String remote, @NonNull String url) {
            return new Result(true, remote, url, true, null);
        }
    }

    /**
     * 在后台线程请求 GitHub API；回调可能在后台线程执行，调用方需切换到主线程更新 UI。
     */
    public static void checkLatestAsync(@NonNull Callback callback) {
        new Thread(() -> callback.onResult(checkLatestBlocking()), "github-release-check").start();
    }

    @NonNull
    public static Result checkLatestBlocking() {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(API_LATEST).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/vnd.github+json");
            conn.setRequestProperty("User-Agent", USER_AGENT);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);

            int code = conn.getResponseCode();
            InputStream stream = code >= 200 && code < 300
                    ? conn.getInputStream() : conn.getErrorStream();
            String body = readUtf8Stream(stream);

            if (code == 404) {
                return Result.failure("no_release");
            }
            if (code != 200) {
                return Result.failure("http_" + code);
            }

            JSONObject json = new JSONObject(body);
            String tag = json.optString("tag_name", "").trim();
            String htmlUrl = json.optString("html_url", "").trim();
            if (tag.isEmpty()) {
                return Result.failure("empty_tag");
            }
            String normalizedRemote = normalizeVersionTag(tag);
            String local = BuildConfig.VERSION_NAME != null ? BuildConfig.VERSION_NAME.trim() : "";
            if (local.isEmpty()) {
                local = "0";
            }

            int cmp = compareSemanticVersions(normalizedRemote, local);
            if (cmp > 0) {
                String displayRemote = tag.startsWith("v") || tag.startsWith("V") ? tag.substring(1) : tag;
                String url = htmlUrl.isEmpty()
                        ? "https://github.com/taisuii/sentry/releases/latest"
                        : htmlUrl;
                return Result.hasUpdate(displayRemote, url);
            }
            return Result.upToDate(normalizedRemote, htmlUrl.isEmpty() ? null : htmlUrl);
        } catch (Exception e) {
            return Result.failure(e.getClass().getSimpleName());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /** 与 {@link #checkLatestBlocking()} 相同逻辑，供单元测试或同步调用 */
    public static boolean shouldSkipCheckDueToCooldown(long lastCheckWallClockMs, long intervalMs) {
        if (lastCheckWallClockMs <= 0) return false;
        return System.currentTimeMillis() - lastCheckWallClockMs < intervalMs;
    }

    public static long defaultCooldownMs() {
        return TimeUnit.HOURS.toMillis(12);
    }

    @NonNull
    static String normalizeVersionTag(@NonNull String tag) {
        String t = tag.trim();
        if (t.startsWith("v") || t.startsWith("V")) {
            t = t.substring(1).trim();
        }
        return t;
    }

    /**
     * 语义版本比较：按点分段比较非负整数部分；未知段视为 0。
     *
     * @return 正数表示 a &gt; b，负数表示 a &lt; b，0 表示相等
     */
    static int compareSemanticVersions(@NonNull String a, @NonNull String b) {
        String[] pa = a.split("\\.");
        String[] pb = b.split("\\.");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            int va = i < pa.length ? leadingIntPart(pa[i]) : 0;
            int vb = i < pb.length ? leadingIntPart(pb[i]) : 0;
            if (va != vb) {
                return Integer.compare(va, vb);
            }
        }
        return 0;
    }

    private static int leadingIntPart(@NonNull String segment) {
        int end = 0;
        while (end < segment.length() && Character.isDigit(segment.charAt(end))) {
            end++;
        }
        if (end == 0) return 0;
        try {
            return Integer.parseInt(segment.substring(0, end));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    @NonNull
    private static String readUtf8Stream(@Nullable InputStream in) throws java.io.IOException {
        if (in == null) return "";
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(in, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }
}
