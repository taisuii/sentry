package anti.rusda;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;

import java.util.ArrayList;
import java.util.List;

import anti.rusda.detector.DetectionResult;
import anti.rusda.ui.adapter.DetectionAdapter;

public class EnvironmentFragment extends Fragment {

    private RecyclerView recyclerView;
    private DetectionAdapter adapter;
    private MaterialButton scanButton;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_environment, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        recyclerView = view.findViewById(R.id.recycler_view);
        scanButton = view.findViewById(R.id.scan_button);
        adapter = new DetectionAdapter();
        recyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        recyclerView.setAdapter(adapter);
        bindScanButton();
    }

    @Override
    public void onResume() {
        super.onResume();
        bindScanButton();
    }

    private void bindScanButton() {
        if (scanButton != null && getActivity() instanceof MainActivity) {
            scanButton.setOnClickListener(((MainActivity) getActivity()).getScanClickListener());
        }
    }

    public void setResults(@NonNull List<DetectionResult> results) {
        if (adapter != null) adapter.setData(new ArrayList<>(results));
    }

    public void setScanning(boolean scanning) {
        if (scanButton != null) scanButton.setEnabled(!scanning);
    }
}
