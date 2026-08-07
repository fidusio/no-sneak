package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.ListSection;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class JobQueuePanel extends JPanel {
    private final AssistantContext ctx;
    private ListSection jobQueueList;

    public JobQueuePanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());
        jobQueueList = ListSection.of(ArrayList::new)
                .title("Job Queue")
                .addButton("+ Add Job", this::onAddJob)
                .label(_ -> "")
                .onEdit(c -> this::onEditJob)
                .onRemove(c -> this::onRemoveJob)
                .scrollable()
                .search("search")
                .build();

        add(jobQueueList);
    }

    private void onAddJob() {

    }

    private void onEditJob() {

    }

    private void onRemoveJob() {

    }
}
