package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.MDViewerPanel;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.function.Consumer;

public class MDFileViewer extends JPanel {

    private static final int PREVIEW_DELAY = 250;

    private final JTextArea editor = new JTextArea();
    private final MDViewerPanel viewer = new MDViewerPanel();
    private final JButton save = new JButton("Save", new IconUtil.SaveIcon(16));
    private final JButton cancel = new JButton("Cancel", new IconUtil.CancelIcon(16));
    private final JButton open = new JButton("Open file");
    private final JLabel status = new JLabel();
    private final TitledBorder editorBorder = BorderFactory.createTitledBorder("Markdown");
    private final JSplitPane split;
    private final Timer preview;

    private Consumer<String> onSave;
    private Runnable onCancel;
    private String committed = "";
    private String loadedFrom;
    private File lastDirectory;
    private boolean dirty;

    public MDFileViewer() {
        this(null, null, null);
    }

    public MDFileViewer(String markdown) {
        this(markdown, null, null);
    }

    public MDFileViewer(String markdown, Consumer<String> onSave, Runnable onCancel) {
        this.onSave = onSave;
        this.onCancel = onCancel;

        setLayout(new BorderLayout());

        editor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, editor.getFont().getSize()));
        editor.setTabSize(2);
        editor.setLineWrap(true);
        editor.setWrapStyleWord(true);
        editor.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        preview = new Timer(PREVIEW_DELAY, e -> viewer.setMarkdown(editor.getText()));
        preview.setRepeats(false);

        editor.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                onEdit();
            }

            public void removeUpdate(DocumentEvent e) {
                onEdit();
            }

            public void changedUpdate(DocumentEvent e) {
                onEdit();
            }
        });

        JScrollPane editorScroll = new JScrollPane(editor);
        editorScroll.setBorder(editorBorder);
        viewer.setBorder(BorderFactory.createTitledBorder("Preview"));

        split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, editorScroll, viewer);
        split.setResizeWeight(0.5);
        split.setContinuousLayout(true);
        split.setOneTouchExpandable(true);

        add(buildToolBar(), BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        bindKey(KeyEvent.VK_S, Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx(), "md-save", this::onSave);
        bindKey(KeyEvent.VK_ESCAPE, 0, "md-cancel", this::onCancel);

        setMarkdown(markdown);
    }

    private JComponent buildToolBar() {
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        bar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        save.addActionListener(e -> onSave());
        cancel.addActionListener(e -> onCancel());
        open.addActionListener(e -> onOpen());
        open.setToolTipText("Load a markdown file into the editor");

        bar.add(save);
        bar.add(cancel);
        bar.addSeparator();
        bar.add(open);
        bar.addSeparator();
        bar.add(status);

        status.setForeground(UIManager.getColor("Label.disabledForeground"));
        updateStatus();
        return bar;
    }

    private void bindKey(int keyCode, int modifiers, String name, Runnable action) {
        editor.getInputMap(WHEN_FOCUSED).put(KeyStroke.getKeyStroke(keyCode, modifiers), name);
        editor.getActionMap().put(name, new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    public MDFileViewer setOnSave(Consumer<String> onSave) {
        this.onSave = onSave;
        return this;
    }

    public MDFileViewer setOnCancel(Runnable onCancel) {
        this.onCancel = onCancel;
        return this;
    }

    public MDFileViewer setSaveText(String text) {
        save.setText(text);
        return this;
    }

    public MDFileViewer setTitle(String title) {
        editorBorder.setTitle(title != null ? title : "Markdown");
        split.getLeftComponent().repaint();
        return this;
    }

    public void setMarkdown(String markdown) {
        editor.setText(markdown != null ? markdown : "");
        editor.setCaretPosition(0);
        loadedFrom = null;
        commit();
    }

    public String getMarkdown() {
        return editor.getText();
    }

    public boolean isDirty() {
        return dirty;
    }

    public void revert() {
        editor.setText(committed);
        editor.setCaretPosition(0);
        loadedFrom = null;
        commit();
    }

    public void markDirty() {
        dirty = true;
        updateStatus();
    }

    public JButton getSaveButton() {
        return save;
    }

    public JButton getCancelButton() {
        return cancel;
    }

    public JTextArea getEditor() {
        return editor;
    }

    public MDViewerPanel getViewer() {
        return viewer;
    }

    public JSplitPane getSplitPane() {
        return split;
    }

    public void load(File source) throws IOException {
        editor.setText(Files.readString(source.toPath(), StandardCharsets.UTF_8));
        editor.setCaretPosition(0);
        loadedFrom = source.getName();
        lastDirectory = source.getParentFile();
        markDirty();
        preview.restart();
    }

    private void onOpen() {
        if (dirty) {
            int res = JOptionPane.showConfirmDialog(this,
                    "Replace the current text with the file contents?",
                    "Open file", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (res != JOptionPane.OK_OPTION) return;
        }

        JFileChooser chooser = new JFileChooser(lastDirectory);
        chooser.setDialogTitle("Open markdown file");
        chooser.setFileFilter(new FileNameExtensionFilter("Markdown files", "md", "markdown", "txt"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        try {
            load(chooser.getSelectedFile());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Could not read the file: " + e.getMessage(),
                    "Open file", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onSave() {
        commit();
        if (onSave != null) onSave.accept(committed);
    }

    private void onCancel() {
        revert();
        if (onCancel != null) onCancel.run();
    }

    private void onEdit() {
        markDirty();
        preview.restart();
    }

    private void commit() {
        preview.stop();
        committed = editor.getText();
        viewer.setMarkdown(committed);
        dirty = false;
        updateStatus();
    }

    private void updateStatus() {
        StringBuilder sb = new StringBuilder();
        if (loadedFrom != null) sb.append("loaded ").append(loadedFrom);
        if (dirty) {
            if (!sb.isEmpty()) sb.append(" · ");
            sb.append("unsaved changes");
        }
        status.setText(sb.toString());
    }
}