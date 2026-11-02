package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.assistant.AIAssistantUtil;
import io.xlogistx.gui.*;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
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
        setName(AIAssistantUtil.ChatHistoryPage.PAGE.getName());
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
        PagePanel page = new PagePanel(AIAssistantUtil.Page.CHAT.getDisplayName(), AIAssistantUtil.ChatHistoryPage.SUBTITLE.getDisplayName());
        JButton newChat = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)), AIAssistantUtil.ChatHistoryPage.NEW_CHAT));
        newChat.addActionListener(_ -> startNewChat());
        page.action(newChat);

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push[][][]"));
        bar.setOpaque(false);
        JTextField search = GUIUtil.applyProp(new JTextField(), AIAssistantUtil.ChatHistoryPage.SEARCH);
        search.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(search, "growx");
        GUIUtil.applyProp(historyCount, AIAssistantUtil.ChatHistoryPage.COUNT);
        historyCount.setForeground(UITokens.muted());
        historyCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(historyCount);
        JButton open = GUIUtil.applyProp(new JButton(new IconUtil.NextIcon(16)), AIAssistantUtil.ChatHistoryPage.OPEN);
        JButton edit = GUIUtil.applyProp(new JButton(new IconUtil.EditIcon(16)), AIAssistantUtil.ChatHistoryPage.EDIT);
        JButton delete = GUIUtil.applyProp(new JButton(new IconUtil.DeleteIcon(16)), AIAssistantUtil.ChatHistoryPage.DELETE);
        delete.setForeground(UITokens.danger());
        for (JButton b : new JButton[]{open, edit, delete}) {
            b.putClientProperty("JButton.buttonType", "toolBarButton");
            b.setEnabled(false);
            bar.add(b);
        }
        page.row(bar);

        GUIUtil.applyProp(historyTable, AIAssistantUtil.ChatHistoryPage.TABLE);
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
        historyCount.setText(all == 0 ? AIAssistantUtil.ChatHistoryPage.COUNT_EMPTY.getDisplayName() : shown == all ? all + " chats" : shown + " of " + all + " chats");
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
        JButton save = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/save.svg", 14, Color.WHITE)), AIAssistantUtil.ChatEditor.SAVE));
        GUIUtil.applyProp(editPromptName, AIAssistantUtil.ChatEditor.EDIT_NAME_FIELD);
        GUIUtil.applyProp(editProviderSelector, AIAssistantUtil.ChatEditor.EDIT_PROVIDER_FIELD);
        GUIUtil.applyProp(editModelSelector, AIAssistantUtil.ChatEditor.EDIT_MODEL_FIELD);
        editModelSelector.setEditable(true);
        bindProviderModels(ctx, editProviderSelector, editModelSelector);

        save.addActionListener(_ -> {
            Object provider = editProviderSelector.getSelectedItem();
            Object model = editModelSelector.getSelectedItem();
            if (provider == null || model == null) {
                JOptionPane.showMessageDialog(this, "Pick a provider and model", AIAssistantUtil.ChatEditor.MISSING_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
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

        return chatForm(AIAssistantUtil.ChatEditor.EDIT_PAGE, editPromptName, editProviderSelector, editModelSelector, save);
    }

    public JPanel buildChatCreator() {
        JButton create = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)), AIAssistantUtil.ChatEditor.CREATE));
        GUIUtil.applyProp(createPromptName, AIAssistantUtil.ChatEditor.NEW_NAME_FIELD);
        GUIUtil.applyProp(createProviderSelector, AIAssistantUtil.ChatEditor.NEW_PROVIDER_FIELD);
        GUIUtil.applyProp(createModelSelector, AIAssistantUtil.ChatEditor.NEW_MODEL_FIELD);
        createModelSelector.setEditable(true);
        bindProviderModels(ctx, createProviderSelector, createModelSelector);

        create.addActionListener(_ -> {
            Object provider = createProviderSelector.getSelectedItem();
            Object model = createModelSelector.getSelectedItem();
            if (provider == null || model == null) {
                JOptionPane.showMessageDialog(this, "Pick a provider and model", AIAssistantUtil.ChatEditor.MISSING_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
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

        return chatForm(AIAssistantUtil.ChatEditor.NEW_PAGE, createPromptName, createProviderSelector, createModelSelector, create);
    }

    /** The create / edit form in the page frame: three rows and a primary button beside Cancel, which returns to the list. */
    private JPanel chatForm(AIAssistantUtil.ChatEditor framing, JTextField name, JComboBox<String> provider,
                            JComboBox<String> model, JButton primary) {
        PagePanel page = new PagePanel(framing.getDisplayName(), framing.getDescription());
        page.setName(framing.getName());
        JPanel form = new JPanel(new MigLayout("insets 20, wrap 2, gapx 16, gapy 10", "[right][360!]"));
        form.setOpaque(false);
        form.add(GUIUtil.applyProp(new JLabel(), AIAssistantUtil.ChatEditor.NAME));
        form.add(name, "growx");
        form.add(GUIUtil.applyProp(new JLabel(), AIAssistantUtil.ChatEditor.PROVIDER));
        form.add(provider, "growx");
        form.add(GUIUtil.applyProp(new JLabel(), AIAssistantUtil.ChatEditor.MODEL));
        form.add(model, "growx");
        JButton cancel = GUIUtil.applyProp(new JButton(), AIAssistantUtil.ChatEditor.CANCEL);
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
                AIAssistantUtil.ChatHistoryPage.DELETE_DIALOG.getDisplayName(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
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
