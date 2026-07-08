package io.xlogistx.nosneak.app.mock.utility;

import com.formdev.flatlaf.FlatClientProperties;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

/**
 * Shared Swing layout helpers used by the mock screens to build split panels,
 * master–detail shells, and simple stacked field forms.
 */
public class PanelBuilder {
    public PanelBuilder() {
    }

    /**
     * Builds a horizontal {@link JSplitPane}.
     *
     * @param left         the left component
     * @param right        the right component
     * @param divLocation  the initial divider location, in pixels
     * @param resizeWeight how extra space is split (0 = all to right, 1 = all to left)
     * @return the configured split pane
     */
    public JSplitPane buildHorizontalSplitView(Component left, Component right, int divLocation, int resizeWeight) {
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
        split.setDividerLocation(divLocation);
        split.setResizeWeight(resizeWeight);

        return split;
    }

    /**
     * Builds the standard master–detail shell: a left sidebar of grouped toggle
     * buttons and the given content on the right.
     *
     * @param content the right-hand detail component
     * @param buttons the left-hand section toggle buttons (added to one {@link ButtonGroup})
     * @return the assembled panel
     */
    public JPanel buildDefaultSplitPanel(JComponent content, JToggleButton... buttons) {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel options = new JPanel();
        options.setLayout(new GridLayout(0, 1, 0, 8));

        ButtonGroup group = new ButtonGroup();

        for (JToggleButton button : buttons) {
            group.add(button);
            options.add(button);
        }

        JPanel optionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        optionsRow.add(options);
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.add(optionsRow, BorderLayout.NORTH);


        // right side that shows selections
        JPanel view = new JPanel(new BorderLayout());
        view.add(content, BorderLayout.CENTER);

        JSplitPane split = buildHorizontalSplitView(new JScrollPane(optionsRow), view, 145, 0);
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    /**
     * Stacks the given components vertically in a single column.
     *
     * @param fields the components to stack, top to bottom
     * @return a panel containing the stacked components
     */
    public JPanel buildJPanelWithFields(JComponent... fields) {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6);
        c.fill = GridBagConstraints.HORIZONTAL;

        c.gridx = 0;
        c.gridwidth = 3;

        for (int i = 0; i < fields.length; i++) {
            c.gridy = i;
            panel.add(fields[i], c);
        }

        return panel;
    }

    public static JPanel row(String label, JButton... buttons) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        row.add(new JLabel(label), BorderLayout.CENTER);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        for (JButton btn : buttons) right.add(btn);
        row.add(right, BorderLayout.EAST);
        return row;
    }

    public static JPanel group(String title, String addLabel, Runnable onAdd) {
        JPanel group = new JPanel();
        group.setLayout(new BoxLayout(group, BoxLayout.Y_AXIS));
        group.setBorder(BorderFactory.createTitledBorder(title));

        JButton add = new JButton(addLabel);
        add.addActionListener(e -> onAdd.run());
        group.add(add);
        return group;
    }

    public static JPanel detail(String title, Runnable onBack, Consumer<JPanel> content) {
        JPanel panel = new JPanel(new MigLayout("wrap 1, insets 10, gapy 6", "[left]"));

        JButton back = new JButton("Back");
        back.addActionListener(e -> onBack.run());
        panel.add(back);
        panel.add(title(title), "gaptop 6, gapbottom 4");

        content.accept(panel);
        return panel;
    }

    public static JPanel listPage(String title, String addLabel, Runnable onAdd, String ...items) {
        JPanel group = group(title, addLabel, onAdd);
        for(String item : items) {
            group.add(row(item, new JButton("edit")));
        }
        return group;
    }

    public static JLabel title(String text) {
        JLabel label = new JLabel(text);
        label.putClientProperty(FlatClientProperties.STYLE_CLASS, "h2");
        return label;
    }
}