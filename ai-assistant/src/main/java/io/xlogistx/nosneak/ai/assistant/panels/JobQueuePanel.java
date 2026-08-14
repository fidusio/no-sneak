package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.ListSection;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

/**
 * The Job Queue page — a stub, and currently without an agreed spec.
 * <p>
 * The list binds to {@code ArrayList::new} (so it is always empty) with a {@code _ -> ""} label,
 * and {@code onAddJob} / {@code onEditJob} / {@code onRemoveJob} are empty bodies. There is
 * nothing here to test and nothing to fix.
 * <p>
 * The module's design doc (§3) describes it as a queue of scans, files and images feedable to a
 * prompt with running → ready → in-prompt states. That write-up predates the composer's
 * {@code +} popup, which now covers per-message attachment of sources, images and captures, so
 * <b>the queue's role is unclear and it is deprioritized</b>. Do not treat §3 as a live
 * requirement — settle what the queue is <i>for</i> against the popup before building it.
 */
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
