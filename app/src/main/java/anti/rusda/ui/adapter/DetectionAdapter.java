package anti.rusda.ui.adapter;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.chip.Chip;

import java.util.ArrayList;
import java.util.List;

import anti.rusda.R;
import anti.rusda.detector.DetectionResult;

public class DetectionAdapter extends RecyclerView.Adapter<DetectionAdapter.ViewHolder> {

    private List<DetectionResult> data = new ArrayList<>();

    public void setData(List<DetectionResult> newData) {
        this.data = newData;
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_detection, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        DetectionResult item = data.get(position);
        holder.bind(item);
    }

    @Override
    public int getItemCount() {
        return data.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        private final MaterialCardView cardView;
        private final TextView titleText;
        private final TextView descriptionText;
        private final TextView detailsTitle;
        private final TextView detailsContent;
        private final ImageView statusIcon;
        private final Chip statusChip;
        private final LinearLayout detailsContainer;
        private final View detailsDivider;
        private final MaterialButton btnCopy;

        public ViewHolder(@NonNull View itemView) {
            super(itemView);
            cardView = (MaterialCardView) itemView;
            titleText = itemView.findViewById(R.id.item_title);
            descriptionText = itemView.findViewById(R.id.item_description);
            detailsTitle = itemView.findViewById(R.id.details_title);
            detailsContent = itemView.findViewById(R.id.details_content);
            statusIcon = itemView.findViewById(R.id.status_icon);
            statusChip = itemView.findViewById(R.id.status_chip);
            detailsContainer = itemView.findViewById(R.id.details_container);
            detailsDivider = itemView.findViewById(R.id.details_divider);
            btnCopy = itemView.findViewById(R.id.btn_copy);
        }

        public void bind(DetectionResult item) {
            titleText.setText(item.getTitle());
            descriptionText.setText(item.getDescription());

            // Set status colors and icons
            int statusColor;
            int statusIconRes;
            int statusBgColor;
            String statusText;

            switch (item.getStatus()) {
                case DetectionResult.STATUS_DANGER:
                    statusColor = ContextCompat.getColor(itemView.getContext(), R.color.status_danger);
                    statusBgColor = ContextCompat.getColor(itemView.getContext(), R.color.status_danger_container);
                    statusIconRes = R.drawable.ic_error;
                    statusText = itemView.getContext().getString(R.string.fail);
                    break;
                case DetectionResult.STATUS_WARNING:
                    statusColor = ContextCompat.getColor(itemView.getContext(), R.color.status_warning);
                    statusBgColor = ContextCompat.getColor(itemView.getContext(), R.color.status_warning_container);
                    statusIconRes = R.drawable.ic_warning;
                    statusText = itemView.getContext().getString(R.string.warn);
                    break;
                default:
                    statusColor = ContextCompat.getColor(itemView.getContext(), R.color.status_healthy);
                    statusBgColor = ContextCompat.getColor(itemView.getContext(), R.color.status_healthy_container);
                    statusIconRes = R.drawable.ic_check;
                    statusText = itemView.getContext().getString(R.string.pass);
                    break;
            }

            statusIcon.setImageResource(statusIconRes);
            statusIcon.setColorFilter(statusColor);
            statusIcon.setBackgroundTintList(ContextCompat.getColorStateList(itemView.getContext(), R.color.sentry_surface_variant));

            statusChip.setText(statusText);
            statusChip.setTextColor(statusColor);
            statusChip.setChipBackgroundColor(ContextCompat.getColorStateList(itemView.getContext(),
                    item.getStatus() == DetectionResult.STATUS_NORMAL ? R.color.status_healthy_container :
                    item.getStatus() == DetectionResult.STATUS_WARNING ? R.color.status_warning_container : R.color.status_danger_container));

            // Setup details
            if (item.getDetails() != null && !item.getDetails().isEmpty()) {
                StringBuilder detailsBuilder = new StringBuilder();
                for (int i = 0; i < item.getDetails().size(); i++) {
                    detailsBuilder.append("• ").append(item.getDetails().get(i));
                    if (i < item.getDetails().size() - 1) {
                        detailsBuilder.append("\n");
                    }
                }
                detailsContent.setText(detailsBuilder.toString());
            } else {
                detailsContent.setText(R.string.no_modifications);
            }

            detailsTitle.setText(item.getDescription());

            // Expand/collapse
            detailsContainer.setVisibility(item.isExpanded() ? View.VISIBLE : View.GONE);

            cardView.setOnClickListener(v -> {
                item.setExpanded(!item.isExpanded());
                detailsContainer.setVisibility(item.isExpanded() ? View.VISIBLE : View.GONE);
            });

            // Copy details to clipboard and show toast
            btnCopy.setOnClickListener(v -> {
                CharSequence text = detailsContent.getText();
                if (text != null && text.length() > 0) {
                    Context ctx = v.getContext();
                    ClipboardManager clipboard = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
                    if (clipboard != null) {
                        clipboard.setPrimaryClip(ClipData.newPlainText("detection_details", text));
                        Toast.makeText(ctx, R.string.copy_to_clipboard, Toast.LENGTH_SHORT).show();
                    }
                }
            });

            // Card stroke based on status
            cardView.setStrokeColor(statusColor);
            cardView.setStrokeWidth(item.isExpanded() ? 2 : 1);
        }
    }
}
