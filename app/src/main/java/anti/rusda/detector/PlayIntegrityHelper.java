package anti.rusda.detector;

import android.content.Context;
import android.util.Base64;

import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;

import java.security.SecureRandom;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Play Integrity API 客户端封装。
 * 获取 token 后需由服务端验证（注入 PlayIntegrityVerifier）。
 * 无 Play 服务或验证失败时合理降级，避免误杀。
 */
public class PlayIntegrityHelper {

    private static final int TIMEOUT_SECONDS = 15;

    private final Context context;
    private final PlayIntegrityVerifier verifier;

    public PlayIntegrityHelper(Context context, PlayIntegrityVerifier verifier) {
        this.context = context;
        this.verifier = verifier;
    }

    public PlayIntegrityHelper(Context context) {
        this(context, null);
    }

    /**
     * 同步执行 Play Integrity 检测。
     * @return [status, summary, detail]
     */
    public String[] runDetectionSync() {
        if (context == null) {
            return new String[]{
                    String.valueOf(DetectionResult.STATUS_WARNING),
                    "No context for Play Integrity",
                    "Play Integrity check skipped"
            };
        }

        IntegrityManager manager = IntegrityManagerFactory.create(context);
        byte[] nonceBytes = new byte[32];
        new SecureRandom().nextBytes(nonceBytes);
        String nonce = Base64.encodeToString(nonceBytes, Base64.NO_WRAP);

        IntegrityTokenRequest request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build();

        final CountDownLatch latch = new CountDownLatch(1);
        final int[] statusHolder = {DetectionResult.STATUS_DANGER};
        final String[] summaryHolder = {"Verification failed"};
        final String[] detailHolder = {"Unknown error"};

        manager.requestIntegrityToken(request)
                .addOnSuccessListener(response -> {
                    String token = response.token();
                    if (verifier != null) {
                        statusHolder[0] = verifier.verifyToken(token);
                        summaryHolder[0] = statusHolder[0] == DetectionResult.STATUS_NORMAL
                                ? "Device integrity verified"
                                : statusHolder[0] == DetectionResult.STATUS_WARNING
                                        ? "Basic integrity only"
                                        : "Integrity verification failed";
                        detailHolder[0] = "Server verified token";
                    } else {
                        statusHolder[0] = DetectionResult.STATUS_WARNING;
                        summaryHolder[0] = "Token obtained, server verification not configured";
                        detailHolder[0] = "Configure PlayIntegrityVerifier for full verification";
                    }
                    latch.countDown();
                })
                .addOnFailureListener(e -> {
                    statusHolder[0] = DetectionResult.STATUS_WARNING;
                    String msg = e != null ? e.getMessage() : "Unknown";
                    if (msg != null && (msg.contains("API_NOT_AVAILABLE") || msg.contains("PLAY_STORE_NOT_FOUND"))) {
                        statusHolder[0] = DetectionResult.STATUS_WARNING;
                        summaryHolder[0] = "Play Services unavailable (emulator or custom ROM?)";
                    } else {
                        summaryHolder[0] = "Play Integrity request failed";
                    }
                    detailHolder[0] = msg != null ? msg : "No details";
                    latch.countDown();
                });

        try {
            if (!latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                statusHolder[0] = DetectionResult.STATUS_WARNING;
                summaryHolder[0] = "Play Integrity request timed out";
                detailHolder[0] = "Request did not complete within " + TIMEOUT_SECONDS + " seconds";
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            statusHolder[0] = DetectionResult.STATUS_WARNING;
            summaryHolder[0] = "Play Integrity check interrupted";
            detailHolder[0] = e.getMessage();
        }

        return new String[]{String.valueOf(statusHolder[0]), summaryHolder[0], detailHolder[0]};
    }
}
