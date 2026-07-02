package io.xlogistx.nosneak.app.mock.utility;

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
    /** One row: a label plus optional Edit/Remove handlers (null hides that button). */
    public record Entry(String label, Runnable onEdit, Runnable onRemove) {}

    private final JPanel rows = new JPanel();
    private final Supplier<List<Entry>> source;

    public ListSection(String title, String addLabel, Runnable onAdd, Supplier<List<Entry>> source) {
        this.source = source;
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder(title));

        rows.setLayout(new BoxLayout(rows, BoxLayout.Y_AXIS));

        JButton add = new JButton(addLabel);
        add.addActionListener(e -> onAdd.run());

        add(rows, BorderLayout.CENTER);
        add(add, BorderLayout.SOUTH);

        refresh();
    }

    /** Rebuilds the rows from the supplier. Call after any add/remove. */
    public void refresh() {
        rows.removeAll();
        for (Entry en : source.get()) {
            List<JButton> buttons = new ArrayList<>();
            if (en.onEdit() != null) {
                JButton edit = new JButton("Edit");
                edit.addActionListener(e -> en.onEdit().run());
                buttons.add(edit);
            }
            if (en.onRemove() != null) {
                JButton remove = new JButton("Remove");
                remove.addActionListener(e -> en.onRemove().run());
                buttons.add(remove);
            }
            rows.add(PanelBuilder.row(en.label(), buttons.toArray(new JButton[0])));
        }
        rows.revalidate();
        rows.repaint();
    }
}
