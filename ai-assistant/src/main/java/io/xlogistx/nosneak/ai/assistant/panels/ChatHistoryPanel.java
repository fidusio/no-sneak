package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.model.AIChat;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.bindProviderModels;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.blankTo;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.deleteConfirm;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.fillProviders;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.selectProvider;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.timestamp;

public class ChatHistoryPanel extends JPanel {

    private final AssistantContext ctx;

    private Runnable onChatOpened;

    public ChatHistoryPanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());
        add(buildHistoryCards());
    }

    public void setOnChatOpened(Runnable onChatOpened) {
        this.onChatOpened = onChatOpened;
    }

    private final CardStack historyCards = new CardStack();
    private ListSection<AIChat> historyList;

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
        historyList = ListSection.of(ctx::getAllChats)
                .title("Chat History")
                .addButton("+ New Chat", this::startNewChat)
                .label(chat -> blankTo(chat.getTitle(), "Untitled chat"))
                .sublabel(this::chatSublabel)
                .onEdit(c -> () -> onEditPrompt(c))
                .onRemove(c -> () -> onRemovePrompt(c))
                .action(new ListSection.RowAction<>(new IconUtil.NextIcon(16), "Open Chat", c -> () -> onOpenChat(c)))
                .emptyText("No chats yet")
                .scrollable()
                .search("search")
                .build();

        return historyList;
    }

    public JPanel buildChatEditor() {
        JButton save = new JButton("Save", new IconUtil.SaveIcon(16));
        editModelSelector.setEditable(true);
        bindProviderModels(ctx, editProviderSelector, editModelSelector);

        save.addActionListener(e -> {
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
                historyCards.show("list");
                refreshHistory();
            });
        });

        return PanelBuilder.detail("Edit Chat", () -> historyCards.show("list"), panel -> {
            PanelBuilder.addRow(panel, "Name", editPromptName);
            PanelBuilder.addRow(panel, "Provider", editProviderSelector);
            PanelBuilder.addRow(panel, "Model", editModelSelector);
            PanelBuilder.addRow(panel, "", save);
        });
    }

    public JPanel buildChatCreator() {
        JButton create = new JButton("Create", new IconUtil.PlusIcon(16));
        bindProviderModels(ctx, createProviderSelector, createModelSelector);

        create.addActionListener(e -> {
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
                ctx.setCurrentChat(temp);
                refreshHistory();
                historyCards.show("list");
                if (onChatOpened != null) onChatOpened.run();
            });
        });

        return PanelBuilder.detail("Create Chat", () -> historyCards.show("list"), panel -> {
            PanelBuilder.addRow(panel, "Name", createPromptName);
            PanelBuilder.addRow(panel, "Provider", createProviderSelector);
            PanelBuilder.addRow(panel, "Model", createModelSelector);
            PanelBuilder.addRow(panel, "", create);
        });
    }

    /**
     * The row's second line. Everything but the title lives here so the search box filters on
     * titles rather than on the timestamps every row carries.
     */
    private String chatSublabel(AIChat chat) {
        AIProvider provider = ctx.lookupProvider(chat.getProvider());
        StringBuilder sb = new StringBuilder(
                (provider != null) ? provider.getName() : blankTo(chat.getProvider(), "no provider"));

        String model = SUS.trimOrNull(chat.getModel());
        if (model != null) sb.append("  ·  ").append(model);

        int messages = chat.getMessages().size();
        sb.append("  ·  ").append(messages).append(messages == 1 ? " message" : " messages");
        sb.append("  ·  created ").append(timestamp(chat.getCreationTime()));
        sb.append("  ·  updated ").append(timestamp(chat.getLastTimeUpdated()));
        return sb.toString();
    }

    public void startNewChat() {
        createPromptName.setText("");
        fillProviders(ctx, createProviderSelector);

        historyCards.show("creator");
    }

    private void onEditPrompt(AIChat chat) {
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
        int res = JOptionPane.showConfirmDialog(this, deleteConfirm(chat.getTitle(), "chat"),
                "Delete chat", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null, () -> ctx.deleteChat(chat), () -> {
            if (chat == selectedChat) selectedChat = null;
            refreshHistory();
        });
    }

    private void onOpenChat(AIChat chat) {
        ctx.setCurrentChat(chat);
        if (onChatOpened != null) onChatOpened.run();
    }

    public void refreshHistory() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshHistory);
            return;
        }
        if (historyList != null) historyList.refresh();
    }

    public void reset() {
        historyCards.show("list");
        selectedChat = null;
    }
}
