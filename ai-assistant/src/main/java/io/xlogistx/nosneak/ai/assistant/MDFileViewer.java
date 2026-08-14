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
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * A standalone markdown editor: a mono text area on the left, a live preview on the right, and an
 * optional metadata form (name / description / type) above them. Re-usable anywhere a markdown
 * string needs editing — it is the skills editor today, and knows nothing about skills.
 * <p>
 * Preview re-renders on a 250 ms timer restarted per keystroke, so typing does not reparse per
 * character; Save, Cancel and {@code setMarkdown} render immediately.
 * <p>
 * <b>Use one instance per host, not one per card.</b> A Swing component has exactly one parent, so
 * putting the same viewer on two cards silently moves it — that is why the skills page has a
 * single editor reused for both create and edit rather than a pair.
 * <p>
 * <b>Open file loads into the buffer; it does not link to the file.</b> The load counts as an edit,
 * not a commit, so Cancel still returns to the original text and nothing reaches the host until
 * Save. There is no write-to-disk path.
 */
public class MDFileViewer extends JPanel {

    private static final int PREVIEW_DELAY = 250;
    private static final int HALF_WIDTH = 420;
    private static final int HALF_HEIGHT = 420;
    private static final int MIN_WIDTH = 160;
    private static final int MIN_HEIGHT = 80;

    public static class MDDocument {

        private final String name;
        private final String description;
        private final Object type;
        private final String markdown;

        public MDDocument(String name, String description, Object type, String markdown) {
            this.name = name;
            this.description = description;
            this.type = type;
            this.markdown = markdown;
        }

        public String getName() {
            return name;
        }

        public String getDescription() {
            return description;
        }

        public Object getType() {
            return type;
        }

        @SuppressWarnings("unchecked")
        public <T> T typeAs() {
            return (T) type;
        }

        public String getMarkdown() {
            return markdown;
        }
    }

    private final JTextArea editor = new JTextArea();
    private final MDViewerPanel viewer = new MDViewerPanel();
    private final JButton save = new JButton("Save", new IconUtil.SaveIcon(16));
    private final JButton cancel = new JButton(new IconUtil.CancelIcon(24));
    private final JButton open = new JButton("Open file");
    private final JLabel status = new JLabel();
    private final TitledBorder editorBorder = BorderFactory.createTitledBorder("Markdown");
    private final JSplitPane split;
    private final Timer preview;

    private final JPanel form = new JPanel(new GridBagLayout());
    private final JTextField nameField = new JTextField(24);
    private final JTextField descriptionField = new JTextField(24);
    private final JComboBox<Object> typeCombo = new JComboBox<>();
    private final JLabel nameLabel = new JLabel("Name");
    private final JLabel descriptionLabel = new JLabel("Description");
    private final JLabel typeLabel = new JLabel("Type");
    private int formRows;
    private boolean nameShown;
    private boolean descriptionShown;
    private boolean typeShown;

    private Consumer<String> onSave;
    private Consumer<MDDocument> onCommit;
    private Predicate<MDDocument> validator;
    private Runnable onCancel;
    private String committed = "";
    private String committedName = "";
    private String committedDescription = "";
    private Object committedType;
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

        editorScroll.setPreferredSize(new Dimension(HALF_WIDTH, HALF_HEIGHT));
        editorScroll.setMinimumSize(new Dimension(MIN_WIDTH, MIN_HEIGHT));
        viewer.setPreferredSize(new Dimension(HALF_WIDTH, HALF_HEIGHT));
        viewer.setMinimumSize(new Dimension(MIN_WIDTH, MIN_HEIGHT));

        split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, editorScroll, viewer);
        split.setResizeWeight(0.5);
        split.setContinuousLayout(true);
        split.setOneTouchExpandable(true);

        JPanel north = new JPanel(new BorderLayout());
        north.add(buildToolBar(), BorderLayout.NORTH);
        north.add(buildForm(), BorderLayout.CENTER);

        add(north, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(buildActions(), BorderLayout.SOUTH);

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
        cancel.setToolTipText("Back — discards unsaved changes");

        bar.add(cancel);
        bar.addSeparator();
        bar.add(status);

        status.setForeground(UIManager.getColor("Label.disabledForeground"));
        updateStatus();
        return bar;
    }

    private JComponent buildActions() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row.add(save);
        row.add(open);
        return row;
    }

    private JComponent buildForm() {
        form.setBorder(BorderFactory.createEmptyBorder(0, 8, 6, 8));
        form.setVisible(false);

        DocumentListener listener = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                updateStatus();
            }

            public void removeUpdate(DocumentEvent e) {
                updateStatus();
            }

            public void changedUpdate(DocumentEvent e) {
                updateStatus();
            }
        };

        nameField.getDocument().addDocumentListener(listener);
        descriptionField.getDocument().addDocumentListener(listener);
        typeCombo.addActionListener(e -> updateStatus());
        return form;
    }

    private void addFormRow(JLabel label, JComponent field) {
        GridBagConstraints labelC = new GridBagConstraints();
        labelC.gridx = 0;
        labelC.gridy = formRows;
        labelC.insets = new Insets(2, 0, 2, 8);
        labelC.anchor = GridBagConstraints.LINE_END;
        form.add(label, labelC);

        GridBagConstraints fieldC = new GridBagConstraints();
        fieldC.gridx = 1;
        fieldC.gridy = formRows;
        fieldC.insets = new Insets(2, 0, 2, 0);
        fieldC.weightx = 1;
        fieldC.fill = GridBagConstraints.HORIZONTAL;
        fieldC.anchor = GridBagConstraints.LINE_START;
        form.add(field, fieldC);

        formRows++;
        form.setVisible(true);
        form.revalidate();
    }

    public MDFileViewer withName(String value) {
        return withName(null, value);
    }

    public MDFileViewer withName(String label, String value) {
        if (label != null) nameLabel.setText(label);
        if (!nameShown) {
            nameShown = true;
            addFormRow(nameLabel, nameField);
        }
        setDocumentName(value);
        return this;
    }

    public MDFileViewer withDescription(String value) {
        return withDescription(null, value);
    }

    public MDFileViewer withDescription(String label, String value) {
        if (label != null) descriptionLabel.setText(label);
        if (!descriptionShown) {
            descriptionShown = true;
            addFormRow(descriptionLabel, descriptionField);
        }
        setDescription(value);
        return this;
    }

    public <T> MDFileViewer withTypes(T[] values, T selected) {
        return withTypes(null, values != null ? Arrays.asList(values) : null, selected, null);
    }

    public <T> MDFileViewer withTypes(T[] values, T selected, Function<? super T, String> renderer) {
        return withTypes(null, values != null ? Arrays.asList(values) : null, selected, renderer);
    }

    public <T> MDFileViewer withTypes(Collection<? extends T> values, T selected) {
        return withTypes(null, values, selected, null);
    }

    @SuppressWarnings("unchecked")
    public <T> MDFileViewer withTypes(String label, Collection<? extends T> values, T selected,
                                      Function<? super T, String> renderer) {
        if (label != null) typeLabel.setText(label);
        if (renderer != null) {
            typeCombo.setRenderer(new DefaultListCellRenderer() {
                @Override
                public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                              boolean isSelected, boolean focused) {
                    super.getListCellRendererComponent(list, value, index, isSelected, focused);
                    if (value != null) setText(renderer.apply((T) value));
                    return this;
                }
            });
        }

        typeCombo.removeAllItems();
        if (values != null) for (T value : values) typeCombo.addItem(value);
        if (!typeShown) {
            typeShown = true;
            addFormRow(typeLabel, typeCombo);
        }
        setSelectedType(selected);
        return this;
    }

    public MDFileViewer setDocumentName(String value) {
        nameField.setText(value != null ? value : "");
        committedName = nameField.getText();
        return this;
    }

    public MDFileViewer setDescription(String value) {
        descriptionField.setText(value != null ? value : "");
        committedDescription = descriptionField.getText();
        return this;
    }

    public MDFileViewer setSelectedType(Object value) {
        typeCombo.setSelectedItem(value);
        committedType = typeCombo.getSelectedItem();
        return this;
    }

    public String getDocumentName() {
        return nameField.getText();
    }

    public String getDescription() {
        return descriptionField.getText();
    }

    @SuppressWarnings("unchecked")
    public <T> T getSelectedType() {
        return (T) typeCombo.getSelectedItem();
    }

    public MDDocument getDocument() {
        return new MDDocument(getDocumentName(), getDescription(), typeCombo.getSelectedItem(), editor.getText());
    }

    public JTextField getNameField() {
        return nameField;
    }

    public JTextField getDescriptionField() {
        return descriptionField;
    }

    public JComboBox<Object> getTypeCombo() {
        return typeCombo;
    }

    private void bindKey(int keyCode, int modifiers, String name, Runnable action) {
        editor.getInputMap(WHEN_FOCUSED).put(KeyStroke.getKeyStroke(keyCode, modifiers), name);
        editor.getActionMap().put(name, new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    /**
     * Fires on Save with the markdown alone — for a host with no metadata rows. Prefer
     * {@link #setOnCommit} when you have used {@link #withName} and friends; both fire if both
     * are set.
     */
    public MDFileViewer setOnSave(Consumer<String> onSave) {
        this.onSave = onSave;
        return this;
    }

    /**
     * Fires on Save with the markdown <i>and</i> the metadata rows (name / description / type)
     * bundled as one {@link MDDocument}. This is the persistence hook for a host using
     * {@link #withName}, {@link #withDescription} or {@link #withTypes}.
     */
    public MDFileViewer setOnCommit(Consumer<MDDocument> onCommit) {
        this.onCommit = onCommit;
        return this;
    }

    /**
     * Gate run <b>before</b> the save callbacks; returning false cancels the save and leaves the
     * editor open with its content intact. The validator is responsible for telling the subject
     * why it refused — this class shows no message of its own.
     */
    public MDFileViewer setValidator(Predicate<MDDocument> validator) {
        this.validator = validator;
        return this;
    }

    /**
     * Runs on Cancel — <b>after</b> the editor has already reverted to the last committed text and
     * field values. A host that only wants "go back" therefore does not need to reload anything to
     * undo the edits.
     */
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
        return dirty || metaDirty();
    }

    public void revert() {
        editor.setText(committed);
        editor.setCaretPosition(0);
        nameField.setText(committedName);
        descriptionField.setText(committedDescription);
        typeCombo.setSelectedItem(committedType);
        loadedFrom = null;
        commit();
    }

    public void markDirty() {
        dirty = true;
        updateStatus();
    }

    private boolean metaDirty() {
        return !nameField.getText().equals(committedName)
                || !descriptionField.getText().equals(committedDescription)
                || !Objects.equals(typeCombo.getSelectedItem(), committedType);
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
        if (isDirty()) {
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
        MDDocument document = getDocument();
        if (validator != null && !validator.test(document)) return;
        commit();
        if (onSave != null) onSave.accept(committed);
        if (onCommit != null) onCommit.accept(document);
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
        committedName = nameField.getText();
        committedDescription = descriptionField.getText();
        committedType = typeCombo.getSelectedItem();
        viewer.setMarkdown(committed);
        dirty = false;
        updateStatus();
    }

    private void updateStatus() {
        StringBuilder sb = new StringBuilder();
        if (loadedFrom != null) sb.append("loaded ").append(loadedFrom);
        if (isDirty()) {
            if (!sb.isEmpty()) sb.append(" · ");
            sb.append("unsaved changes");
        }
        status.setText(sb.toString());
    }
}