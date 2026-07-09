package io.xlogistx.nosneak.app.mock.utility;

import com.formdev.flatlaf.extras.FlatSVGIcon;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * A titled, refreshable list of rows with an "add" button and optional per-row
 * Edit/Remove actions. Rows are pulled from a {@link Supplier} on each {@link #refresh()},
 * so the caller owns the data source and this component just renders it.
 */
public class ListSection extends JPanel {
    /**
     * One row: a label plus optional Edit/Remove handlers (null hides that button).
     */
    public record Entry(String label, Runnable onEdit, Runnable onRemove) {
    }

    private final JPanel rows = new JPanel();
    private final Supplier<List<Entry>> source;

    public ListSection(String title, String addLabel, Runnable onAdd, Supplier<List<Entry>> source) {
        this.source = source;
        setLayout(new BorderLayout());
        // Plain outline (no embedded text) + padding, with the larger h2 title on top.
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)));
        add(PanelBuilder.title(title), BorderLayout.NORTH);

        rows.setLayout(new BoxLayout(rows, BoxLayout.Y_AXIS));

        if (onAdd != null) {
            JButton add = new JButton(addLabel);
            add.addActionListener(_ -> onAdd.run());

            add(add, BorderLayout.SOUTH);
        }
        add(rows, BorderLayout.CENTER);

        refresh();
    }

    /**
     * Rebuilds the rows from the supplier. Call after any add/remove.
     */
    public void refresh() {
        rows.removeAll();
        for (Entry en : source.get()) {
            List<JButton> buttons = new ArrayList<>();
            if (en.onEdit() != null) {
                JButton edit = new JButton(new FlatSVGIcon("icons/pencil.svg", 16, 16));
                edit.setToolTipText("Edit");
                edit.addActionListener(_ -> en.onEdit().run());
                buttons.add(edit);
            }
            if (en.onRemove() != null) {
                JButton remove = new JButton(new FlatSVGIcon("icons/trash.svg", 16, 16));
                remove.setToolTipText("Remove");
                remove.addActionListener(_ -> en.onRemove().run());
                buttons.add(remove);
            }
            rows.add(PanelBuilder.row(en.label(), buttons.toArray(new JButton[0])));
        }
        rows.revalidate();
        rows.repaint();
    }
}
