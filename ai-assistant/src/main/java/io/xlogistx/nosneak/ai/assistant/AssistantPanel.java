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
import java.util.HashSet;
import java.util.List;
import java.util.Set;


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

    private final CardStack promptCards = new CardStack();

    private final CardStack skillsCards = new CardStack();
    private final JTextField skillName = new JTextField(20);
    private final JTextField skillDescription = new JTextField(20);
    private final JTextArea skillInstructions = new JTextArea(6, 20);

    private final JTextField editSkillName = new JTextField(20);
    private final JTextField editSkillDescription = new JTextField(20);
    private final JTextArea editSkillInstructions = new JTextArea(6, 20);
    private AISkill selectedSkill;

    private final CardStack historyCards = new CardStack();
    private final JTextField editPromptName = new JTextField();
    private final JComboBox<String> editProviderSelector = new JComboBox<>();
    private final JComboBox<String> editModelSelector = new JComboBox<>();

    private final CardStack providerCards = new CardStack();
    private ListSection<APIKey<String>> providerAddList;

    private final JTextField createPromptName = new JTextField();
    private final JComboBox<String> createProviderSelector = new JComboBox<>();
    private final JComboBox<String> createModelSelector = new JComboBox<>();
    private AIChat selectedChat;

    private JLabel chatTitle;

    private JButton sendButton;
    private JButton attachSkillButton;
    private final List<AISkill> pendingSkills = new ArrayList<>();

    private final JCheckBox sendFullHistory = new JCheckBox("Send history", true);

    private JComboBox<String> modelSelector;

    JToggleButton chatButton = new JToggleButton("Chat");
    JToggleButton jobQueueButton = new JToggleButton("Job Queue");
    JToggleButton historyButton = new JToggleButton("History");
    JToggleButton skillsButton = new JToggleButton("Skills");
    JToggleButton providersButton = new JToggleButton("Providers");
    JToggleButton captureButton = new JToggleButton("Capture");

    public AssistantPanel(AssistantContext context) {
        this.context = context;

        reloadProviders();

        setLayout(new BorderLayout());

        cardStack.add(buildPromptCards(), "chat");
        cardStack.add(new JScrollPane(buildJobQueuePanel()), "queue");
        cardStack.add(new JScrollPane(buildHistoryCards()), "history");
        cardStack.add(new JScrollPane(buildSkillCards()), "skills");
        cardStack.add(new JScrollPane(buildProviderCardsPanel()), "providers");
        cardStack.add(new JScrollPane(buildScreenCapturePanel()), "capture");

        chatButton.addActionListener(_ -> cardStack.show("chat"));
        jobQueueButton.addActionListener(_ -> cardStack.show("queue"));
        historyButton.addActionListener(_ -> cardStack.show("history"));
        skillsButton.addActionListener(_ -> cardStack.show("skills"));
        providersButton.addActionListener(_ -> cardStack.show("providers"));
        captureButton.addActionListener(_ -> cardStack.show("capture"));

        ButtonGroup selectorGroup = new ButtonGroup();
        selectorGroup.add(chatButton);
        selectorGroup.add(jobQueueButton);
        selectorGroup.add(historyButton);
        selectorGroup.add(skillsButton);
        selectorGroup.add(providersButton);
        selectorGroup.add(captureButton);
        chatButton.setSelected(true);

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), chatButton, captureButton, jobQueueButton, historyButton, skillsButton, providersButton));

        context.onChange("currentChat", e -> refreshPrompt());
    }

    public JPanel buildPromptCards() {
        promptCards.add(buildEmptyChat(), "empty");
        promptCards.add(buildPromptPanel(), "prompt");

        promptCards.show("empty");
        JPanel p = new JPanel(new BorderLayout());
        p.add(promptCards.view(), BorderLayout.CENTER);
        return p;
    }

    public JPanel buildEmptyChat() {
        JPanel out = new JPanel();
        out.add(new JLabel("No chat selected, create one in the history tab"));

        return out;
    }

    public JPanel buildPromptPanel() {
        transcript = new JPanel(new MigLayout("wrap 1, insets 14, gapy 10", "[grow]"));

        AIChat chat = context.currentChat();
        String titleText = (chat != null && chat.getTitle() != null) ? chat.getTitle() : "Default chat";
        chatTitle = PanelBuilder.title(titleText);

        modelSelector = new JComboBox<>();
        modelSelector.setEditable(true);

        sendFullHistory.setToolTipText(
                "Checked: each request carries the whole conversation. Unchecked: only the new message is sent.");

        JPanel titlePanel = new JPanel(new FlowLayout());
        titlePanel.add(chatTitle);
        titlePanel.add(modelSelector);
        titlePanel.add(sendFullHistory);

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
        composerScroll.setBorder(BorderFactory.createEmptyBorder());
        composerScroll.setOpaque(false);
        composerScroll.getViewport().setOpaque(false);

        attachSkillButton = new JButton(new IconUtil.PlusIcon(16));

        attachSkillButton.addActionListener(_ -> showAttachPopup());

        attachSkillButton.putClientProperty("JButton.buttonType", "toolBarButton");
        attachSkillButton.setFocusable(false);
        refreshSkillTooltip();
        attachSkillButton.setMargin(new Insets(0, 0, 0, 0));
        attachSkillButton.setPreferredSize(new Dimension(28, 28));

        JPanel addSkillHolder = new JPanel(new BorderLayout());
        addSkillHolder.setOpaque(false);
        addSkillHolder.add(attachSkillButton, BorderLayout.NORTH);

        JPanel inputBox = new JPanel(new BorderLayout(4, 0));
        inputBox.setBackground(composer.getBackground());
        inputBox.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")),
                BorderFactory.createEmptyBorder(4, 6, 4, 4)));
        inputBox.add(addSkillHolder, BorderLayout.WEST);
        inputBox.add(composerScroll, BorderLayout.CENTER);

        sendButton = new JButton("Send");
        sendButton.addActionListener(_ -> onSend());

        JPanel composerBar = new JPanel(new BorderLayout(8, 0));
        composerBar.setBorder(BorderFactory.createEmptyBorder(8, 14, 12, 14));
        composerBar.add(inputBox, BorderLayout.CENTER);
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
        historyList = ListSection.of(context::getAllChats)
                .title("History")
                .addButton("+ New Prompt", this::onAddPrompt)
                .label(AIChat::getTitle)
                .onEdit(c -> () -> onEditPrompt(c))
                .onRemove(c -> () -> onRemovePrompt(c))
                .action(new ListSection.RowAction<>(new IconUtil.NextIcon(16), "Open Chat", c -> () -> onOpenChat(c)))
                .emptyText("No chats yet")
                .build();

        return historyList;
    }

    public JPanel buildChatEditor() {
        JButton save = new JButton("Save", new IconUtil.SaveIcon(16));
        editProviderSelector.setEditable(true);
        editModelSelector.setEditable(true);
        bindProviderModels(editProviderSelector, editModelSelector);

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
            BackgroundTask.runCatching(this, save, () -> context.saveChat(selectedChat), () -> {
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
        bindProviderModels(createProviderSelector, createModelSelector);

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
            BackgroundTask.runCatching(this, create, () -> context.saveChat(temp), () -> {
                context.setCurrentChat(temp);
                refreshHistory();
                historyCards.show("list");
                promptCards.show("prompt");
                cardStack.show("chat");
                chatButton.setSelected(true);
            });
        });

        return PanelBuilder.detail("Create Chat", () -> historyCards.show("list"), panel -> {
            PanelBuilder.addRow(panel, "Name", createPromptName);
            PanelBuilder.addRow(panel, "Provider", createProviderSelector);
            PanelBuilder.addRow(panel, "Model", createModelSelector);
            PanelBuilder.addRow(panel, "", create);
        });
    }

    public JPanel buildSkillCards() {
        skillsCards.add(buildSkillPanel(), "list");
        skillsCards.add(buildSkillEditor(), "editor");
        skillsCards.add(buildSkillCreator(), "creator");

        skillsCards.show("list");
        JPanel p = new JPanel(new BorderLayout());
        p.add(skillsCards.view(), BorderLayout.CENTER);
        return p;
    }

    public JPanel buildSkillPanel() {
        skillsList = ListSection.of(context::getAllSkills)
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
        JButton save = new JButton("Save", new IconUtil.SaveIcon(16));

        save.addActionListener(e -> {
            String name = editSkillName.getText();
            String description = editSkillDescription.getText();
            String content = editSkillInstructions.getText();

            if (!name.isEmpty()) selectedSkill.setName(name);
            if (!description.isEmpty()) selectedSkill.setDescription(description);
            if (!content.isEmpty()) selectedSkill.setContent(content);

            BackgroundTask.runCatching(this, save, () -> context.saveSkill(selectedSkill), () -> {
                refreshSkills();
                skillsCards.show("list");
            });
        });

        return PanelBuilder.detail("Skill", () -> skillsCards.show("list"), panel -> {
            editSkillInstructions.setLineWrap(true);
            editSkillInstructions.setWrapStyleWord(true);

            PanelBuilder.addRow(panel, "Name", editSkillName);
            PanelBuilder.addRow(panel, "Description", editSkillDescription);
            PanelBuilder.addRow(panel, "Skill Instructions", editSkillInstructions);
            PanelBuilder.addRow(panel, "", save);
        });
    }

    public JPanel buildSkillCreator() {
        JButton create = new JButton("Create", new IconUtil.PlusIcon(16));

        create.addActionListener(e -> {
            String name = skillName.getText();
            String description = skillDescription.getText();
            String content = skillInstructions.getText();

            AISkill skill = new AISkill();
            skill.setName(name);
            skill.setDescription(description);
            skill.setContent(content);

            BackgroundTask.runCatching(this, create, () -> context.saveSkill(skill), () -> {
                refreshSkills();
                skillsCards.show("list");
            });

        });

        return PanelBuilder.detail("Skill", () -> skillsCards.show("list"), panel -> {
            skillInstructions.setLineWrap(true);
            skillInstructions.setWrapStyleWord(true);

            PanelBuilder.addRow(panel, "Name", skillName);
            PanelBuilder.addRow(panel, "Description", skillDescription);
            PanelBuilder.addRow(panel, "Skill Instructions", skillInstructions);
            PanelBuilder.addRow(panel, "", create);
        });
    }

    public JPanel buildProviderCardsPanel() {
        providerCards.add(buildProviderPanel(), "list");
        providerCards.add(buildAddProvider(), "add");

        providerCards.show("list");
        JPanel p = new JPanel(new BorderLayout());
        p.add(providerCards.view(), BorderLayout.CENTER);
        return p;
    }

    public JPanel buildProviderPanel() {
        providerList = ListSection.of(
                        context::getProvidersList
                )
                .title("Providers")
                .addButton(" + Add Key", this::onAddProvider)
                .label(AIProvider::getName)
                .emptyText("No providers")
                .onEdit(p -> () -> onEditProvider(p))
                .onRemove(p -> () -> onRemoveProvider(p))
                .build();

        return providerList;
    }

    public JPanel buildAddProvider() {
        providerAddList = ListSection.of(this::availableKeys)
                .title("Nickname  *  Provider (if any)")
                .label(this::keyLabel)
                .emptyText("No keys available. Add one in NoSneak credentials.")
                .action(new ListSection.RowAction<>(new IconUtil.PlusIcon(16), "Add to assistant",
                        k -> () -> onSelectAddKey(k)))
                .build();

        return PanelBuilder.detail("Add a key", () -> providerCards.show("list"),
                content -> content.add(providerAddList, "growx"));
    }

    private List<APIKey<String>> availableKeys() {
        Set<String> enabled = new HashSet<>();
        for (APIKey<String> k : context.getCredentials().enabledAPIKeys()) {
            if (k.getAPIKey() != null) enabled.add(k.getAPIKey());
        }
        List<APIKey<String>> out = new ArrayList<>();
        for (APIKey<String> k : context.getCredentials().APIKeys()) {
            if (enabled.contains(k.getAPIKey())) continue;
            out.add(k);
        }
        return out;
    }

    private String keyLabel(APIKey<String> key) {
        String provider = providerOf(key);
        if (AIAPIProvider.resolveType(provider) != null) return key.getName() + "  ·  " + provider;
        return key.getName() + "  ·  choose provider";
    }

    private String providerOf(APIKey<String> key) {
        Object v = (key.getProperties() != null) ? key.getProperties().getValue("provider") : null;
        return v == null ? null : v.toString();
    }

    private static final String[] PROVIDER_DISPLAY = {"OpenAI", "Anthropic (Claude)", "Google (Gemini)", "Grok (xAI)"};
    private static final String[] PROVIDER_CANONICAL = {"openai", "anthropic", "gemini", "grok"};

    private String promptProviderType(APIKey<String> key) {
        JComboBox<String> combo = new JComboBox<>(PROVIDER_DISPLAY);
        int res = JOptionPane.showConfirmDialog(this, combo, "Provider for " + key.getName(),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return null;
        return PROVIDER_CANONICAL[combo.getSelectedIndex()];
    }

    private void onSelectAddKey(APIKey<String> key) {
        if (AIAPIProvider.resolveType(providerOf(key)) == null) {
            String chosen = promptProviderType(key);
            if (chosen == null) return;
            if (key.getProperties() != null) key.getProperties().build("provider", chosen);
        }
        BackgroundTask.run(this, null,
                () -> {
                    context.getCredentials().setEnabled(key, true);
                    AIAPIProvider p = AIAPIProvider.create(key);
                    if (p != null) {
                        try {
                            p.getModelCatalog().refresh();
                        } catch (Exception ignore) {
                        }
                    }
                    return p;
                },
                p -> {
                    if (p != null) context.getProviders().put(p.getName(), p);
                    if (providerList != null) providerList.refresh();
                    if (providerAddList != null) providerAddList.refresh();
                    providerCards.show("list");
                });
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
        promptCards.show(chat == null ? "empty" : "prompt");
        chatTitle.setText(chat != null && chat.getTitle() != null ? chat.getTitle() : "Default chat");
        fillModels(modelSelector, chat != null ? chat.getProvider() : null);

        transcript.removeAll();
        if (chat != null) {
            modelSelector.setSelectedItem(chat.getModel());
            for (NVEntity e : chat.getMessages().values()) {
                AIMessage m = (AIMessage) e;
                AIRequest req = m.getAIRequest();
                if (req != null && req.getContent() != null) addMessage(req.getContent(), true, null, null);
                AIResponse res = m.getAIResponse();
                if (res != null && res.getContent() != null)
                    addMessage(res.getContent(), false, latencyOf(res), tokensOf(res));
            }
        }
        transcript.revalidate();
        transcript.repaint();
    }

    private void onSend() {

        if (sendButton == null || !sendButton.isEnabled()) return;

        String text = composer.getText().trim();
        if (text.isEmpty()) return;

        AIChat chat = context.currentChat();
        if (chat == null) {
            JOptionPane.showMessageDialog(this, "Open a chat first (History > + New Prompt)",
                    "Send", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Object sel = modelSelector.getSelectedItem();
        if (sel == null || sel.toString().isBlank()) {
            JOptionPane.showMessageDialog(this, "Pick a model first",
                    "Send", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        AIProvider p = context.getProviders().lookup(chat.getProvider());
        if (p == null) {
            JOptionPane.showMessageDialog(this,
                    "Provider \"" + chat.getProvider() + "\" is not linked. Add its key on the Providers page.",
                    "Send", JOptionPane.WARNING_MESSAGE);
            return;
        }

        AIRequest request = new AIRequest();
        request.setContent(text);
        request.setMaxTokens(1024);
        request.setModel(sel.toString());
        chat.setModel(sel.toString());

        AIMessage msg = new AIMessage(request);
        chat.addMessage(msg);
        addMessage(text, true, null, null);
        composer.setText("");
        composer.requestFocusInWindow();

        StringBuilder sb = new StringBuilder();

        if (sendFullHistory.isSelected()) {

            for (NVEntity e : chat.getMessages().values()) {
                AIMessage m = (AIMessage) e;
                AIRequest req = m.getAIRequest();
                AIResponse res = m.getAIResponse();
                if (req != null && req.getContent() != null)
                    sb.append("Human: ").append(req.getContent()).append("\n\n");
                if (res != null && res.getContent() != null)
                    sb.append("Assistant: ").append(res.getContent()).append("\n\n");
            }
            sb.append("Assistant:");
        } else {
            sb.append(text);
        }

        AIRequest wire = new AIRequest();
        wire.setModel(request.getModel());
        wire.setMaxTokens(request.getMaxTokens());
        wire.setProviderSessionID(chat.getProviderSessionID());
        wire.setContent(sb.toString());

        StringBuilder skillSb = new StringBuilder();
        for (AISkill s : pendingSkills) {
            if (s.getContent() == null || s.getContent().isEmpty()) continue;
            if (!skillSb.isEmpty()) skillSb.append("\n\n");
            skillSb.append("<skill>").append(s.getContent()).append("</skill>");
        }

        final AIChat sending = chat;
        sendButton.setEnabled(false);
        try {
            p.asyncSend(wire, skillSb.toString(), new AssistantCallback(context, sending, msg,
                    resp -> {
                        sendButton.setEnabled(true);
                        if (sending == context.currentChat() && resp.getContent() != null && !resp.getContent().isEmpty())
                            addMessage(resp.getContent(), false, latencyOf(resp), tokensOf(resp));
                    }, err -> {
                sendButton.setEnabled(true);
                if (sending == context.currentChat()) {
                    refreshPrompt();
                    if (composer.getText().isBlank()) composer.setText(text);
                }
                JOptionPane.showMessageDialog(this, "Send failed: " + err.getMessage(), "Send", JOptionPane.ERROR_MESSAGE);
            }));
        } catch (Exception e) {
            sendButton.setEnabled(true);
            sending.getMessages().remove(msg);
            if (sending == context.currentChat()) {
                refreshPrompt();
                if (composer.getText().isBlank()) composer.setText(text);
            }
            JOptionPane.showMessageDialog(this, "Send failed: " + e.getMessage(),
                    "Send", JOptionPane.ERROR_MESSAGE);
            return;
        }
        pendingSkills.clear();
        refreshSkillTooltip();
    }

    private void showAttachPopup() {
        JPopupMenu popup = new JPopupMenu();
        JPanel content = new JPanel(new MigLayout("wrap 1, insets 10 12 10 12, gapy 4", "[grow]"));
        content.setOpaque(false);

        content.add(sectionLabel("Skills for this message"));
        List<AISkill> skills = context.getAllSkills();
        if (skills.isEmpty()) {
            JLabel none = new JLabel("No skills yet");
            none.setEnabled(false);
            content.add(none);
        } else {
            for (AISkill skill : skills) {
                JCheckBox box = new JCheckBox(skill.getName(), pendingSkills.contains(skill));
                box.setOpaque(false);
                if (skill.getDescription() != null && !skill.getDescription().isEmpty())
                    box.setToolTipText(skill.getDescription());
                box.addActionListener(_ -> {
                    if (box.isSelected()) {
                        if (!pendingSkills.contains(skill)) pendingSkills.add(skill);
                    } else {
                        pendingSkills.remove(skill);
                    }
                    refreshSkillTooltip();
                });
                content.add(box);
            }
        }

        popup.add(content);
        popup.show(attachSkillButton, 0, -popup.getPreferredSize().height);
    }

    private static JLabel sectionLabel(String text) {
        JLabel label = new JLabel(text.toUpperCase());
        label.setFont(label.getFont().deriveFont(Font.BOLD, label.getFont().getSize2D() - 2f));
        label.setForeground(UIManager.getColor("Label.disabledForeground"));
        return label;
    }

    private void refreshSkillTooltip() {
        if (attachSkillButton == null) return;
        if (pendingSkills.isEmpty()) {
            attachSkillButton.setToolTipText("Attach skills to the next message");
            return;
        }
        StringBuilder names = new StringBuilder();
        for (AISkill s : pendingSkills) {
            if (!names.isEmpty()) names.append(", ");
            names.append(s.getName());
        }
        attachSkillButton.setToolTipText("Skills for the next message: " + names);
    }

    private static Integer latencyOf(AIResponse res) {
        return (res != null && res.getLatency() > 0) ? (int) res.getLatency() : null;
    }

    private static Integer tokensOf(AIResponse res) {
        return (res != null && res.getTokens() > 0) ? res.getTokens() : null;
    }

    private void addMessage(String response, boolean user, Integer latency, Integer tokens) {
        JComponent bubble = chatBubble(response, user, latency, tokens);
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
        if (chat == null) return;
        int res = JOptionPane.showConfirmDialog(this, "Delete \"" + chat.getTitle() + "\"?",
                "Delete chat", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null, () -> context.deleteChat(chat), () -> {
            if (chat == selectedChat) selectedChat = null;
            refreshHistory();
        });
    }

    private void onOpenChat(AIChat chat) {
        context.setCurrentChat(chat);
        promptCards.show("prompt");
        cardStack.show("chat");
        chatButton.setSelected(true);
    }

    private void onAddSkill() {
        skillName.setText("");
        skillDescription.setText("");
        skillInstructions.setText("");
        skillsCards.show("creator");
    }

    private void onEditSkill(AISkill skill) {
        if (skill == null) return;
        selectedSkill = skill;
        editSkillName.setText(selectedSkill.getName());
        editSkillDescription.setText(selectedSkill.getDescription());
        editSkillInstructions.setText(selectedSkill.getContent());
        skillsCards.show("editor");
    }

    private void onRemoveSkill(AISkill skill) {
        if (skill == null) return;
        int res = JOptionPane.showConfirmDialog(this, "Delete \"" + skill.getName() + "\"?",
                "Delete skill", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null, () -> context.deleteSkill(skill), () -> {
            if (selectedSkill == skill) selectedSkill = null;
            refreshSkills();
        });
    }

    private void onEditProvider(AIProvider provider) {
        if (provider == null || provider.getAPIKey() == null) return;
        APIKey<String> key = provider.getAPIKey();
        String chosen = promptProviderType(key);
        if (chosen == null) return;
        if (key.getProperties() != null) key.getProperties().build("provider", chosen);

        BackgroundTask.run(this, null,
                () -> {
                    context.getCredentials().setEnabled(key, true);
                    AIAPIProvider rebuilt = AIAPIProvider.create(key);
                    if (rebuilt != null) {
                        try {
                            rebuilt.getModelCatalog().refresh();
                        } catch (Exception ignore) {
                        }
                    }
                    return rebuilt;
                },
                rebuilt -> {
                    if (rebuilt != null) context.getProviders().put(rebuilt.getName(), rebuilt);
                    if (providerList != null) providerList.refresh();
                });
    }

    private void onAddProvider() {
        if (providerAddList != null) providerAddList.refresh();
        providerCards.show("add");
    }


    private void onRemoveProvider(AIProvider provider) {
        if (provider == null) return;
        BackgroundTask.run(this, null,
                () -> {
                    if (provider.getAPIKey() != null)
                        context.getCredentials().setEnabled(provider.getAPIKey(), false);
                    return null;
                },
                _ -> {
                    context.getProviders().getCacheMap().remove(provider.getName());
                    if (providerList != null) providerList.refresh();
                    if (providerAddList != null) providerAddList.refresh();
                });
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
            List<AIProvider> built = new ArrayList<>();
            for (APIKey<String> key : context.getCredentials().enabledAPIKeys()) {
                AIAPIProvider p = AIAPIProvider.create(key);
                if (p == null) continue;
                try {
                    p.getModelCatalog().refresh();
                } catch (Exception ignore) {
                }
                built.add(p);
            }
            return built;
        }, built -> {
            for (AIProvider p : built) context.getProviders().put(p.getName(), p);
            if (providerList != null) providerList.refresh();
        });

    }

    public void refreshHistory() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshHistory);
            return;
        }
        if (historyList != null) historyList.refresh();
    }

    public void refreshSkills() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshSkills);
            return;
        }
        if (skillsList != null) skillsList.refresh();
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

    public void resetPanel() {
        context.resetContext();
        sendFullHistory.setSelected(true);
        pendingSkills.clear();
        refreshSkillTooltip();
        composer.setText("");
        promptCards.show("empty");
        cardStack.show("chat");
        historyCards.show("list");
        skillsCards.show("list");
        chatButton.setSelected(true);
        selectedChat = null;
        selectedSkill = null;
    }
}
