package anti.rusda;

import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import java.util.ArrayList;
import java.util.List;

import anti.rusda.detector.DetectionManager;
import anti.rusda.detector.DetectionResult;
import anti.rusda.ui.adapter.DetectionAdapter;

public class MainActivity extends BaseActivity {

    static {
        System.loadLibrary("antifrida");
    }

    private RecyclerView recyclerView;
    private DetectionAdapter adapter;
    private DetectionManager detectionManager;
    private LinearProgressIndicator scanProgress;
    private MaterialButton scanButton;
    private MaterialCardView statusCard;
    private ImageView statusIconLarge;
    private TextView statusTitle;
    private TextView statusSummary;
    private LinearLayout emptyState;
    private LinearLayout scanProgressContainer;
    private TextView scanProgressText;
    private ChipGroup filterChips;

    private List<DetectionResult> lastResults = new ArrayList<>();
    private boolean hasScanned = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        setupRecyclerView();
        setupListeners();
        setupFilterChips();
        setupToolbar();

        detectionManager = new DetectionManager(this);
        updateStatusForEmptyState();
    }

    private void initViews() {
        recyclerView = findViewById(R.id.recycler_view);
        scanProgress = findViewById(R.id.scan_progress);
        scanButton = findViewById(R.id.scan_button);
        statusCard = findViewById(R.id.status_card);
        statusIconLarge = findViewById(R.id.status_icon_large);
        statusTitle = findViewById(R.id.status_title);
        statusSummary = findViewById(R.id.status_summary);
        emptyState = findViewById(R.id.empty_state);
        scanProgressContainer = findViewById(R.id.scan_progress_container);
        scanProgressText = findViewById(R.id.scan_progress_text);
        filterChips = findViewById(R.id.filter_chips);
    }

    private void setupToolbar() {
        MaterialToolbar toolbar = findViewById(R.id.toolbar);
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
            // Language changed, restart activity to apply
            Intent intent = new Intent(this, MainActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
            finish();
            startActivity(intent);
        }
    }

    private void setupRecyclerView() {
        adapter = new DetectionAdapter();
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        recyclerView.setAdapter(adapter);
    }

    private void setupListeners() {
        scanButton.setOnClickListener(v -> runDetection());
    }

    private void setupFilterChips() {
        filterChips.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if (checkedIds.isEmpty()) return;
            int checkedId = checkedIds.get(0);
            filterResults(checkedId);
        });
    }

    private void filterResults(int filterId) {
        if (lastResults.isEmpty()) return;

        List<DetectionResult> filtered = new ArrayList<>();
        for (DetectionResult result : lastResults) {
            if (filterId == R.id.chip_all) {
                filtered.add(result);
            } else if (filterId == R.id.chip_failed) {
                if (result.getStatus() == DetectionResult.STATUS_DANGER) {
                    filtered.add(result);
                }
            } else if (filterId == R.id.chip_warning) {
                if (result.getStatus() == DetectionResult.STATUS_WARNING) {
                    filtered.add(result);
                }
            } else if (filterId == R.id.chip_passed) {
                if (result.getStatus() == DetectionResult.STATUS_NORMAL) {
                    filtered.add(result);
                }
            }
        }
        adapter.setData(filtered);
    }

    private void updateStatusForEmptyState() {
        statusIconLarge.setImageResource(R.drawable.ic_help);
        statusIconLarge.setColorFilter(getColor(R.color.status_unknown));
        statusTitle.setText(R.string.environment_unknown);
        statusSummary.setText(R.string.never);
        scanButton.setText(R.string.run_scan);
    }

    private void runDetection() {
        showLoading(true);
        emptyState.setVisibility(View.GONE);
        recyclerView.setVisibility(View.VISIBLE);
        hasScanned = true;

        new Thread(() -> {
            List<DetectionResult> results = detectionManager.runAllDetections();
            lastResults = results;

            runOnUiThread(() -> {
                adapter.setData(results);
                updateStatusCard(results);
                showLoading(false);
                animateResults();
            });
        }).start();
    }

    private void updateStatusCard(List<DetectionResult> results) {
        int failedCount = 0;
        int warningCount = 0;
        int passedCount = 0;

        for (DetectionResult result : results) {
            switch (result.getStatus()) {
                case DetectionResult.STATUS_DANGER:
                    failedCount++;
                    break;
                case DetectionResult.STATUS_WARNING:
                    warningCount++;
                    break;
                case DetectionResult.STATUS_NORMAL:
                    passedCount++;
                    break;
            }
        }

        String summary = getString(R.string.result_summary, failedCount, warningCount, passedCount);
        statusSummary.setText(summary);

        if (failedCount > 0) {
            statusIconLarge.setImageResource(R.drawable.ic_error);
            statusIconLarge.setColorFilter(getColor(R.color.status_danger));
            statusTitle.setText(R.string.environment_risk);
            statusCard.setStrokeColor(getColor(R.color.status_danger));
        } else if (warningCount > 0) {
            statusIconLarge.setImageResource(R.drawable.ic_warning);
            statusIconLarge.setColorFilter(getColor(R.color.status_warning));
            statusTitle.setText(R.string.environment_risk);
            statusCard.setStrokeColor(getColor(R.color.status_warning));
        } else {
            statusIconLarge.setImageResource(R.drawable.ic_check_circle);
            statusIconLarge.setColorFilter(getColor(R.color.status_healthy));
            statusTitle.setText(R.string.environment_healthy);
            statusCard.setStrokeColor(getColor(R.color.status_healthy));
        }

        scanButton.setText(R.string.rescan);

        // Update filter chips visibility
        filterChips.setVisibility(View.VISIBLE);
    }

    private void showLoading(boolean show) {
        scanProgressContainer.setVisibility(show ? View.VISIBLE : View.GONE);
        scanButton.setEnabled(!show);
        filterChips.setVisibility(show ? View.GONE : (hasScanned ? View.VISIBLE : View.GONE));
    }

    private void animateResults() {
        ObjectAnimator animator = ObjectAnimator.ofFloat(recyclerView, "alpha", 0f, 1f);
        animator.setDuration(500);
        animator.setInterpolator(new AccelerateDecelerateInterpolator());
        animator.start();
    }

    // Native methods
    public native boolean nativeDetectFridaThread();
    public native boolean nativeDetectFridaPort();
    public native boolean nativeDetectFridaMemory();
    public native boolean nativeDetectDebugMode();
    public native boolean nativeDetectHook();
    public native String nativeGetDetectionDetails();
}
