package anti.rusda.detector;

import java.util.ArrayList;
import java.util.List;

public class DetectionResult {
    public static final int STATUS_NORMAL = 0;
    public static final int STATUS_WARNING = 1;
    public static final int STATUS_DANGER = 2;

    private String title;
    private String description;
    private int status;
    private List<String> details;
    private boolean expanded;

    public DetectionResult(String title, String description, int status) {
        this.title = title;
        this.description = description;
        this.status = status;
        this.details = new ArrayList<>();
        this.expanded = false;
    }

    public DetectionResult(String title, String description, int status, List<String> details) {
        this.title = title;
        this.description = description;
        this.status = status;
        this.details = details != null ? details : new ArrayList<>();
        this.expanded = false;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public List<String> getDetails() {
        return details;
    }

    public void setDetails(List<String> details) {
        this.details = details;
    }

    public void addDetail(String detail) {
        if (this.details == null) {
            this.details = new ArrayList<>();
        }
        this.details.add(detail);
    }

    public boolean isExpanded() {
        return expanded;
    }

    public void setExpanded(boolean expanded) {
        this.expanded = expanded;
    }

    public String getStatusText() {
        switch (status) {
            case STATUS_NORMAL:
                return "Normal";
            case STATUS_WARNING:
                return "Warning";
            case STATUS_DANGER:
                return "Danger";
            default:
                return "Unknown";
        }
    }
}
