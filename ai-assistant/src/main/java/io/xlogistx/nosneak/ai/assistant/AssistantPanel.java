package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.model.*;
import io.xlogistx.nosneak.ai.AIException;
import io.xlogistx.nosneak.ai.AIProvider;
import org.zoxweb.shared.security.APIKey;

import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.util.NVEntity;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Objects;

import static io.xlogistx.nosneak.ai.assistant.AssistantUtil.chatBubble;

public class AssistantPanel extends JPanel {

    private final CardStack cardStack = new CardStack();
    private final AssistantContext context;

    // Repopulated by refresh() so the list tracks login/logout (credentials() is empty until login).

    private ListSection<AISkill> skillsList;
    private ListSection<AIChat> historyList;
    private ListSection jobQueueList;
    private ListSection<AIProvider> providerList;
    private ListSection captureList;

    private JPanel transcript;
    private JScrollPane transcriptScroll;
    private JTextArea composer;

    private final CardStack skillsCards = new CardStack();
    private final JTextField skillName = new JTextField(20);
    private final JTextArea skillInstructions = new JTextArea(6, 20);
    private AISkill selectedSkill;

    private final CardStack historyCards = new CardStack();
    private final JTextField editPromptName = new JTextField();
    private final JComboBox<String> editProviderSelector = new JComboBox<>();
    private final JComboBox<String> editModelSelector = new JComboBox<>();

    private final JTextField createPromptName = new JTextField();
    private final JComboBox<String> createProviderSelector = new JComboBox<>();
    private final JComboBox<String> createModelSelector = new JComboBox<>();
    private AIChat selectedChat;

    private JLabel chatTitle;

    private JButton sendButton;

    private JComboBox<String> modelSelector;

    public AssistantPanel(AssistantContext context) {
        this.context = context;

        reloadProviders();

        setLayout(new BorderLayout());

        cardStack.add(buildPromptPanel(), "chat");
        cardStack.add(new JScrollPane(buildJobQueuePanel()), "queue");
        cardStack.add(new JScrollPane(buildHistoryCards()), "history");
        cardStack.add(new JScrollPane(buildSkillsPanel()), "skills");
        cardStack.add(new JScrollPane(buildProvidersPanel()), "providers");
        cardStack.add(new JScrollPane(buildScreenCapturePanel()), "capture");

        JToggleButton chatButton = new JToggleButton("Chat");
        chatButton.addActionListener(_ -> cardStack.show("chat"));

        JToggleButton jobQueueButton = new JToggleButton("Job Queue");
        jobQueueButton.addActionListener(_ -> cardStack.show("queue"));

        JToggleButton historyButton = new JToggleButton("History");
        historyButton.addActionListener(_ -> cardStack.show("history"));

        JToggleButton skillsButton = new JToggleButton("Skills");
        skillsButton.addActionListener(_ -> cardStack.show("skills"));

        JToggleButton providersButton = new JToggleButton("Providers");
        providersButton.addActionListener(_ -> cardStack.show("providers"));

        JToggleButton captureButton = new JToggleButton("Capture");
        captureButton.addActionListener(_ -> cardStack.show("capture"));

        ButtonGroup group = new ButtonGroup();
        group.add(chatButton);
        group.add(jobQueueButton);
        group.add(historyButton);
        group.add(skillsButton);
        group.add(providersButton);
        group.add(captureButton);
        chatButton.setSelected(true);

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), chatButton, captureButton, jobQueueButton, historyButton, skillsButton, providersButton));

        context.onChange("currentChat", e -> refreshPrompt());
    }

    public JPanel buildPromptPanel() {
        transcript = new JPanel(new MigLayout("wrap 1, insets 14, gapy 10", "[grow]"));

        AIChat chat = context.currentChat();
        String titleText = (chat != null && chat.getTitle() != null) ? chat.getTitle() : "Default chat";
        chatTitle = PanelBuilder.title(titleText);

        modelSelector = new JComboBox<>();
        modelSelector.setEditable(true);

        JPanel titlePanel = new JPanel(new FlowLayout());
        titlePanel.add(chatTitle);
        titlePanel.add(modelSelector);

        transcriptScroll = new JScrollPane(transcript,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        transcriptScroll.setBorder(BorderFactory.createEmptyBorder());
        transcriptScroll.getVerticalScrollBar().setUnitIncrement(16);

        composer = new JTextArea(1, 20);
        composer.setLineWrap(true);
        composer.setWrapStyleWord(true);
        composer.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        composer.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "chat-send");
        composer.getActionMap().put("chat-send", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                onSend();
            }
        });
        composer.getInputMap().put(
                KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.SHIFT_DOWN_MASK), "insert-break");

        JScrollPane composerScroll = new JScrollPane(composer,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        composerScroll.setPreferredSize(new Dimension(0, 44));

        sendButton = new JButton("Send");
        sendButton.addActionListener(_ -> onSend());

        JPanel composerBar = new JPanel(new BorderLayout(8, 0));
        composerBar.setBorder(BorderFactory.createEmptyBorder(8, 14, 12, 14));
        composerBar.add(composerScroll, BorderLayout.CENTER);
        composerBar.add(sendButton, BorderLayout.EAST);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(titlePanel, BorderLayout.NORTH);
        panel.add(transcriptScroll, BorderLayout.CENTER);
        panel.add(composerBar, BorderLayout.SOUTH);
        return panel;
    }


    public JPanel buildJobQueuePanel() {
        jobQueueList = ListSection.of(ArrayList::new)
                .title("Job Queue")
                .addButton("+ Add Job", this::onAddJob)
                .label(_ -> "")
                .onEdit(c -> this::onEditJob)
                .onRemove(c -> this::onRemoveJob)
                .build();

        return jobQueueList;
    }

    public JPanel buildJobEditor() {
        return new JPanel();
    }

    private JPanel buildHistoryCards() {
        historyCards.add(buildHistoryPanel(), "list");
        historyCards.add(buildChatEditor(), "editor");
        historyCards.add(buildChatCreator(), "creator");
        historyCards.show("list");
        JPanel p = new JPanel(new BorderLayout());
        p.add(historyCards.view(), BorderLayout.CENTER);
        return p;
    }

    public JPanel buildHistoryPanel() {
        historyList = ListSection.of(() -> context.getChats().getAllChats())
                .title("History")
                .addButton("+ New Prompt", this::onAddPrompt)
                .label(AIChat::getTitle)
                .onEdit(c -> () -> onEditPrompt(c))
                .onRemove(c -> () -> onRemovePrompt(c))
                .emptyText("No chats yet")
                .build();

        return historyList;
    }

    public JPanel buildChatEditor() {
        JButton save = new JButton("Save", new IconUtil.SaveIcon(16));
        bindProviderModels(editProviderSelector, editModelSelector);

        save.addActionListener(e -> {
            selectedChat.setTitle(editPromptName.getText());
            selectedChat.setModel(Objects.requireNonNull(editModelSelector.getSelectedItem()).toString());
            selectedChat.setProvider(Objects.requireNonNull(editProviderSelector.getSelectedItem()).toString());
            historyCards.show("list");
            historyList.refresh();
        });

        return PanelBuilder.detail("Edit Chat", () -> historyCards.show("list"), panel -> {
            PanelBuilder.addRow(panel, "Name", editPromptName);
            PanelBuilder.addRow(panel, "Provider", editProviderSelector);
            PanelBuilder.addRow(panel, "Model", editModelSelector);
            PanelBuilder.addRow(panel, "", save);
        });
    }

    public JPanel buildChatCreator() {
        JButton save = new JButton("Create", new IconUtil.PlusIcon(16));
        bindProviderModels(createProviderSelector, createModelSelector);

        save.addActionListener(e -> {
            AIChat temp = new AIChat(createPromptName.getText());
            temp.setModel(Objects.requireNonNull(createModelSelector.getSelectedItem()).toString());

            temp.setProvider(Objects.requireNonNull(createProviderSelector.getSelectedItem()).toString());
            context.setCurrentChat(temp);

            cardStack.show("chat");
        });

        return PanelBuilder.detail("Create Chat", () -> historyCards.show("list"), panel -> {
            PanelBuilder.addRow(panel, "Name", createPromptName);
            PanelBuilder.addRow(panel, "Provider", createProviderSelector);
            PanelBuilder.addRow(panel, "Model", createModelSelector);
            PanelBuilder.addRow(panel, "", save);
        });
    }

    public JPanel buildSkillsPanel() {
        skillsList = ListSection.of(context::getSkills)
                .title("Skills")
                .addButton("+ New Skill", this::onAddSkill)
                .label(AISkill::getName)
                .onEdit(c -> () -> onEditSkill(c))
                .onRemove(c -> () -> onRemoveSkill(c))
                .emptyText("No Skills yet")
                .build();

        return skillsList;
    }

    public JPanel buildSkillEditor() {
        return new JPanel();
    }

    public JPanel buildProvidersPanel() {
        providerList = ListSection.of(
                        () -> new ArrayList<>(context.getProviders().getCacheMap().values())
                )
                .title("Providers")
                .label(AIProvider::getName)
                .emptyText("No providers")
                .action(new ListSection.RowAction<>(new IconUtil.RefreshIcon(16), "Refresh models",
                        p -> () -> onRefreshProvider(p)))
                .onRemove(p -> () -> onRemoveProvider(p))
                .build();

        return providerList;
    }

    public JPanel buildScreenCapturePanel() {
        JButton selectAreaButton = new JButton("Select Area", new IconUtil.AreaIcon(16));
        selectAreaButton.addActionListener(_ -> onSelectArea());

        JButton captureButton = new JButton("Capture", new IconUtil.CameraIcon(16));
        captureButton.addActionListener(_ -> onAddCapture());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(selectAreaButton);
        buttons.add(captureButton);

        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        header.add(PanelBuilder.title("Capture"), BorderLayout.WEST);
        header.add(buttons, BorderLayout.EAST);

        captureList = ListSection.of(ArrayList::new)
                .title("")
                .label(_ -> "")
                .onEdit(p -> this::onEditCaptureDetails)
                .onRemove(p -> this::onRemoveCapture)
                .action(new ListSection.RowAction<>(new IconUtil.AreaIcon(16), "Edit Capture Location", p -> this::onEditCaptureLocation))
                .emptyText("No Captures yet")
                .build();

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(header, BorderLayout.NORTH);
        panel.add(captureList, BorderLayout.CENTER);
        return panel;
    }

    private void refreshPrompt() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshPrompt);
            return;
        }

        AIChat chat = context.currentChat();
        chatTitle.setText(chat != null && chat.getTitle() != null ? chat.getTitle() : "Default chat");
        fillModels(modelSelector, chat != null ? chat.getProvider() : null);

        transcript.removeAll();
        if (chat != null) {
            modelSelector.setSelectedItem(chat.getModel());
            for (NVEntity e : chat.getMessages().values()) {
                AIMessage m = (AIMessage) e;
                AIRequest req = m.getAIRequest();
                if (req != null && req.getContent() != null) addMessage(req.getContent(), true);
                AIResponse res = m.getAIResponse();
                if (res != null && res.getContent() != null) addMessage(res.getContent(), false);
            }
        }
        transcript.revalidate();
        transcript.repaint();
    }

    private void onSend() {

        if (sendButton == null || !sendButton.isEnabled()) return;

        String text = composer.getText().trim();
        if (text.isEmpty()) return;

        AIRequest request = new AIRequest();
        request.setContent(text);
        request.setMaxTokens(1024);


        AIChat chat = context.currentChat();
        if (chat == null) return;
        Object sel = modelSelector.getSelectedItem();
        if (sel == null) return;
        request.setModel(sel.toString());

        AIProvider p = context.getProviders().lookup(chat.getProvider());
        if (p == null) return;
        addMessage(text, true);
        composer.setText("");
        composer.requestFocusInWindow();
        BackgroundTask.run(this, sendButton, () -> p.send(request), this::onResponse);
    }

    private void addMessage(String text, boolean user) {
        JComponent bubble = chatBubble(text, user);
        String cons = user
                ? "growx, wmax 78%, alignx trailing"
                : "growx, wmax 92%, alignx leading";
        transcript.add(bubble, cons);
        transcript.revalidate();
        transcript.repaint();

        SwingUtilities.invokeLater(() -> {
            JScrollBar v = transcriptScroll.getVerticalScrollBar();
            v.setValue(v.getMaximum());
        });
    }

    private void onResponse(AIResponse response) {
        String text = response.getContent();
        if (text == null || text.isEmpty()) return;
        addMessage(text, false);
    }

    private void onAddJob() {

    }

    private void onEditJob() {

    }

    private void onRemoveJob() {

    }

    private void onAddPrompt() {
        createPromptName.setText("");
        fillProviders(createProviderSelector);

        historyCards.show("creator");
    }

    private void onEditPrompt(AIChat chat) {
        this.selectedChat = chat;
        fillProviders(editProviderSelector);
        editPromptName.setText(chat.getTitle());
        editProviderSelector.setSelectedItem(chat.getProvider());
        editModelSelector.setSelectedItem(chat.getModel());
        historyCards.show("editor");

    }

    private void onRemovePrompt(AIChat chat) {
        context.deleteChat(chat);
        selectedChat = null;
        historyList.refresh();
    }

    private void onAddSkill() {

    }

    private void onEditSkill(AISkill skill) {

    }

    private void onRemoveSkill(AISkill skill) {

    }

    private void onRefreshProvider(AIProvider provider) {
        BackgroundTask.run(this, null,
                () -> {
                    provider.getModelCatalog().refresh();
                    return null;
                },
                r -> {
                    if (providerList != null) providerList.refresh();
                });
    }

    private void onRemoveProvider(AIProvider provider) {

    }

    private void onAddCapture() {

    }

    private void onSelectArea() {

    }

    private void onEditCaptureLocation() {

    }

    private void onEditCaptureDetails() {

    }

    private void onRemoveCapture() {

    }

    public void reloadProviders() {
        BackgroundTask.run(this, null, () -> {
            for (APIKey<String> key : context.getCredentials().APIKeys()) {
                try {
                    context.addProvider(key);
                } catch (Exception ignore) {
                }
            }
            for (AIProvider p : context.getProviders().getCacheMap().values()) {
                try {
                    p.getModelCatalog().refresh();
                } catch (Exception ignore) {
                }
            }
            return null;
        }, r -> {
            if (providerList != null) providerList.refresh();
        });
    }

    public void clearProviders() {
        context.clearProviders();
        fillProviders(createProviderSelector);
        fillProviders(editProviderSelector);
        if (providerList != null) providerList.refresh();
        if (modelSelector != null) modelSelector.removeAllItems();

    }

    private void fillProviders(JComboBox<String> box) {
        box.removeAllItems();
        for (String name : context.getProviders().getCacheMap().keySet()) box.addItem(name);
    }

    private void fillModels(JComboBox<String> box, String providerName) {
        box.removeAllItems();
        AIProvider p = context.getProviders().lookup(providerName);
        if (p == null) return;
        try {
            String[] models = p.getModelCatalog().models();
            if (models != null) for (String m : models) box.addItem(m);
        } catch (AIException _) {
        }
    }

    private void bindProviderModels(JComboBox<String> providerBox, JComboBox<String> modelBox) {
        providerBox.addActionListener(_ -> fillModels(modelBox, (String) providerBox.getSelectedItem()));
    }

}
