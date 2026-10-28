package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.AssistantPanel;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIResponse;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.List;
import java.util.regex.Pattern;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.bindProviderModels;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.deleteConfirm;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.fillProviders;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.selectProvider;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.timestamp;

/**
 * The list of chats — the Chat page itself since the merge of 2026-10-26 (the open conversation
 * is {@link ChatPanel}'s other card): a {@link PagePanel} head with the one primary action
 * (New chat), a toolbar (search, count, Open / Edit / Delete on the selected row) and a styled
 * table on {@link ChatHistoryModel}, newest update first; double-click opens. The create and
 * edit forms are two further cards in the same frame. Opening a chat is
 * {@code context.setCurrentChat}, which the Chat page listens to.
 */
public class ChatHistoryPanel extends JPanel {

    private final AssistantContext ctx;

    private Runnable onFormClosed;

    public ChatHistoryPanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());
        add(buildHistoryCards());
    }

    /** Told when a form (Edit chat's Save or Cancel, New chat's Cancel) returns to the list. */
    public void setOnFormClosed(Runnable onFormClosed) {
        this.onFormClosed = onFormClosed;
    }

    /** Back to the list from a form, and tell the owner. */
    private void closeForm() {
        selectedChat = null;
        historyCards.show("list");
        if (onFormClosed != null) onFormClosed.run();
    }

    /** The facts line of a chat: {@code provider · model · N messages}. */
    public String facts(AIChat chat) {
        return historyModel.facts(chat);
    }

    /** @see ChatHistoryModel#replyMeta(AIResponse) */
    public String replyMeta(AIResponse res) {
        return historyModel.replyMeta(res);
    }

    private final CardStack historyCards = new CardStack();
    private final ChatHistoryModel historyModel = new ChatHistoryModel(this::providerName);
    private final JTable historyTable = new JTable(historyModel);
    private final TableRowSorter<ChatHistoryModel> historySorter = new TableRowSorter<>(historyModel);
    private final JLabel historyCount = new JLabel();

    private final JTextField editPromptName = new JTextField();
    private final JComboBox<String> editProviderSelector = new JComboBox<>();
    private final JComboBox<String> editModelSelector = new JComboBox<>();

    private final JTextField createPromptName = new JTextField();
    private final JComboBox<String> createProviderSelector = new JComboBox<>();
    private final JComboBox<String> createModelSelector = new JComboBox<>();
    private AIChat selectedChat;

    private JComponent buildHistoryCards() {
        historyCards.add(buildHistoryPanel(), "list");
        historyCards.add(buildChatEditor(), "editor");
        historyCards.add(buildChatCreator(), "creator");
        historyCards.show("list");
        return historyCards.view();
    }

    public JPanel buildHistoryPanel() {
        PagePanel page = new PagePanel(AssistantPanel.Page.CHAT.getDisplayName(),
                "Every chat you had with the assistant, kept in this store under your account only. Open one to continue it, or start a new one.");
        JButton newChat = UITokens.primary(new JButton("New chat", IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)));
        newChat.addActionListener(_ -> startNewChat());
        page.action(newChat);

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push[][][]"));
        bar.setOpaque(false);
        JTextField search = new JTextField();
        search.putClientProperty("JTextField.placeholderText", "Search by title, provider or model");
        search.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(search, "growx");
        historyCount.setForeground(UITokens.muted());
        historyCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(historyCount);
        JButton open = new JButton("Open", new IconUtil.NextIcon(16));
        JButton edit = new JButton("Edit", new IconUtil.EditIcon(16));
        JButton delete = new JButton("Delete", new IconUtil.DeleteIcon(16));
        delete.setForeground(UITokens.danger());
        for (JButton b : new JButton[]{open, edit, delete}) {
            b.putClientProperty("JButton.buttonType", "toolBarButton");
            b.setEnabled(false);
            bar.add(b);
        }
        page.row(bar);

        Tables.style(historyTable);
        Tables.width(historyTable, ChatHistoryModel.COL_TITLE, 320);
        Tables.width(historyTable, ChatHistoryModel.COL_PROVIDER, 140);
        Tables.width(historyTable, ChatHistoryModel.COL_MODEL, 200);
        Tables.width(historyTable, ChatHistoryModel.COL_MESSAGES, 90);
        Tables.width(historyTable, ChatHistoryModel.COL_CREATED, 140);
        Tables.width(historyTable, ChatHistoryModel.COL_UPDATED, 140);
        TimestampRenderer when = new TimestampRenderer();
        historyTable.getColumnModel().getColumn(ChatHistoryModel.COL_CREATED).setCellRenderer(when);
        historyTable.getColumnModel().getColumn(ChatHistoryModel.COL_UPDATED).setCellRenderer(when);
        historyTable.setRowSorter(historySorter);
        historySorter.setSortKeys(List.of(new RowSorter.SortKey(ChatHistoryModel.COL_UPDATED, SortOrder.DESCENDING)));
        historyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        historyTable.getSelectionModel().addListSelectionListener(_ -> {
            boolean one = historyTable.getSelectedRowCount() == 1;
            for (JButton b : new JButton[]{open, edit, delete}) b.setEnabled(one);
        });
        historyTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) onOpenChat(selectedRow());
            }
        });
        open.addActionListener(_ -> onOpenChat(selectedRow()));
        edit.addActionListener(_ -> editChat(selectedRow()));
        delete.addActionListener(_ -> onRemovePrompt(selectedRow()));
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                filter();
            }

            public void removeUpdate(DocumentEvent e) {
                filter();
            }

            public void changedUpdate(DocumentEvent e) {
                filter();
            }

            private void filter() {
                String q = search.getText().trim();
                historySorter.setRowFilter(q.isEmpty() ? null : RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
                updateCount();
            }
        });
        JScrollPane scroll = new JScrollPane(historyTable);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(UITokens.surface());
        page.card(scroll);
        updateCount();
        return page;
    }

    /** The selected chat, or null when no row is selected. */
    private AIChat selectedRow() {
        int row = historyTable.getSelectedRow();
        return row < 0 ? null : historyModel.rowAt(historyTable.convertRowIndexToModel(row));
    }

    private void updateCount() {
        int shown = historyTable.getRowCount();
        int all = historyModel.getRowCount();
        historyCount.setText(all == 0 ? "No chats yet" : shown == all ? all + " chats" : shown + " of " + all + " chats");
    }

    /** The provider column's text for a config reference: the provider's name, or null when unknown. */
    private String providerName(String ref) {
        AIProvider provider = ctx.lookupProvider(ref);
        return provider != null ? provider.getName() : null;
    }

    /** {@code yyyy-MM-dd HH:mm} for the two timestamp columns, muted like the scan history's. */
    private static final class TimestampRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setText(value instanceof Long l ? timestamp(l) : "");
            if (!isSelected) setForeground(UITokens.muted());
            return this;
        }
    }

    public JPanel buildChatEditor() {
        JButton save = UITokens.primary(new JButton("Save", IconUtil.svgIcon("io/xlogistx/gui/icons/save.svg", 14, Color.WHITE)));
        editModelSelector.setEditable(true);
        bindProviderModels(ctx, editProviderSelector, editModelSelector);

        save.addActionListener(_ -> {
            Object provider = editProviderSelector.getSelectedItem();
            Object model = editModelSelector.getSelectedItem();
            if (provider == null || model == null) {
                JOptionPane.showMessageDialog(this, "Pick a provider and model", "Missing selection", JOptionPane.WARNING_MESSAGE);
                return;
            }
            selectedChat.setTitle(editPromptName.getText());
            selectedChat.setModel(model.toString());
            selectedChat.setProvider(provider.toString());
            BackgroundTask.runCatching(this, save, () -> ctx.saveChat(selectedChat), () -> {
                refreshHistory();
                closeForm();
            });
        });

        return chatForm("Edit chat", "Rename the chat, or change the provider and model it talks to.",
                editPromptName, editProviderSelector, editModelSelector, save);
    }

    public JPanel buildChatCreator() {
        JButton create = UITokens.primary(new JButton("Create", IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)));
        createModelSelector.setEditable(true);
        bindProviderModels(ctx, createProviderSelector, createModelSelector);

        create.addActionListener(_ -> {
            Object provider = createProviderSelector.getSelectedItem();
            Object model = createModelSelector.getSelectedItem();
            if (provider == null || model == null) {
                JOptionPane.showMessageDialog(this, "Pick a provider and model", "Missing selection", JOptionPane.WARNING_MESSAGE);
                return;
            }
            AIChat temp = new AIChat(createPromptName.getText());
            temp.setModel(model.toString());
            temp.setProvider(provider.toString());
            BackgroundTask.runCatching(this, create, () -> ctx.saveChat(temp), () -> {
                refreshHistory();
                historyCards.show("list");
                ctx.setCurrentChat(temp); // the Chat page shows the conversation on this
            });
        });

        return chatForm("New chat", "Name it and pick the provider and model it will talk to.",
                createPromptName, createProviderSelector, createModelSelector, create);
    }

    /** The create / edit form in the page frame: three rows and a primary button beside Cancel, which returns to the list. */
    private JPanel chatForm(String title, String description, JTextField name, JComboBox<String> provider,
                            JComboBox<String> model, JButton primary) {
        PagePanel page = new PagePanel(title, description);
        JPanel form = new JPanel(new MigLayout("insets 20, wrap 2, gapx 16, gapy 10", "[right][360!]"));
        form.setOpaque(false);
        form.add(new JLabel("Name"));
        form.add(name, "growx");
        form.add(new JLabel("Provider"));
        form.add(provider, "growx");
        form.add(new JLabel("Model"));
        form.add(model, "growx");
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(_ -> closeForm());
        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 8"));
        actions.setOpaque(false);
        actions.add(primary);
        actions.add(cancel);
        form.add(actions, "skip 1, gaptop 8");
        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);
        top.add(form, BorderLayout.NORTH);
        page.card(top);
        return page;
    }

    public void startNewChat() {
        createPromptName.setText("");
        fillProviders(ctx, createProviderSelector);

        historyCards.show("creator");
    }

    /** Opens the Edit chat form on {@code chat} (the list's Edit, or the conversation's). */
    public void editChat(AIChat chat) {
        if (chat == null) return;
        this.selectedChat = chat;
        fillProviders(ctx, editProviderSelector);
        editPromptName.setText(chat.getTitle());
        selectProvider(ctx, editProviderSelector, chat.getProvider());
        editModelSelector.setSelectedItem(chat.getModel());
        historyCards.show("editor");
    }

    public void refreshProviderCombos() {
        fillProviders(ctx, createProviderSelector);
        fillProviders(ctx, editProviderSelector);
    }

    private void onRemovePrompt(AIChat chat) {
        if (chat == null) return;
        int res = JOptionPane.showConfirmDialog(this, deleteConfirm(ChatHistoryModel.title(chat), "chat"),
                "Delete chat", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null, () -> ctx.deleteChat(chat), () -> {
            if (chat == selectedChat) selectedChat = null;
            refreshHistory();
        });
    }

    private void onOpenChat(AIChat chat) {
        if (chat == null) return;
        ctx.setCurrentChat(chat); // the Chat page shows the conversation on this
    }

    /** Re-reads the chats (EDT-safe) and keeps the selected row by GUID when it survives. */
    public void refreshHistory() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshHistory);
            return;
        }
        AIChat keep = selectedRow();
        historyModel.setRows(ctx.getAllChats());
        updateCount();
        if (keep != null && keep.getGUID() != null) {
            for (int i = 0; i < historyModel.getRowCount(); i++) {
                if (keep.getGUID().equals(historyModel.rowAt(i).getGUID())) {
                    int view = historyTable.convertRowIndexToView(i);
                    historyTable.setRowSelectionInterval(view, view);
                    break;
                }
            }
        }
    }

    public void reset() {
        historyCards.show("list");
        selectedChat = null;
    }
}
