package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.model.*;
import io.xlogistx.nosneak.ai.AIException;
import io.xlogistx.nosneak.ai.AIProvider;
import org.zoxweb.shared.security.APIKey;

import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.data.ReferenceIDDAO;
import org.zoxweb.shared.util.NVEntity;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;


import static io.xlogistx.nosneak.ai.assistant.AssistantUtil.chatBubble;

public class AssistantPanel extends JPanel {

    private static final DateTimeFormatter ROW_TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

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
    private MDFileViewer skillEditor;
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
    JToggleButton historyButton = new JToggleButton("Chat History");
    JToggleButton skillsButton = new JToggleButton("Skills");
    JToggleButton providersButton = new JToggleButton("Providers");
    JToggleButton captureButton = new JToggleButton("Capture");

    public AssistantPanel(AssistantContext context) {
        this.context = context;

        reloadProviders();

        setLayout(new BorderLayout());

        cardStack.add(buildPromptCards(), "chat");
        cardStack.add(new JScrollPane(buildHistoryCards()), "history");
        cardStack.add(new JScrollPane(buildJobQueuePanel()), "queue");
        cardStack.add(buildSkillCards(), "skills");
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

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), chatButton, historyButton, captureButton, jobQueueButton, skillsButton, providersButton));

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
        JLabel title = new JLabel("No chat selected");
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize2D() + 4f));
        title.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel hint = new JLabel("Start a new chat, or pick one up from your history");
        hint.setForeground(UIManager.getColor("Label.disabledForeground"));
        hint.setAlignmentX(Component.CENTER_ALIGNMENT);

        JButton newChat = new JButton("New Chat", new IconUtil.PlusIcon(16));
        newChat.addActionListener(_ -> openChatCreator());

        JButton openHistory = new JButton("Open Chat History");
        openHistory.putClientProperty("JButton.buttonType", "borderless");
        openHistory.addActionListener(_ -> historyButton.doClick());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
        buttons.setOpaque(false);
        buttons.add(newChat);
        buttons.add(openHistory);
        buttons.setAlignmentX(Component.CENTER_ALIGNMENT);

        JPanel stack = new JPanel();
        stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
        stack.setOpaque(false);
        stack.add(title);
        stack.add(Box.createVerticalStrut(6));
        stack.add(hint);
        stack.add(Box.createVerticalStrut(16));
        stack.add(buttons);

        JPanel out = new JPanel(new GridBagLayout());
        out.add(stack);
        return out;
    }

    private void openChatCreator() {
        historyButton.doClick();
        onAddPrompt();
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

        JButton newChat = new JButton("New Chat", new IconUtil.PlusIcon(16));
        newChat.setToolTipText("Create a new chat");
        newChat.addActionListener(_ -> openChatCreator());

        JPanel titlePanel = new JPanel(new FlowLayout());
        titlePanel.add(chatTitle);
        titlePanel.add(modelSelector);
        titlePanel.add(sendFullHistory);
        titlePanel.add(newChat);

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
                .scrollable()
                .search("search")
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
                .title("Chat History")
                .addButton("+ New Chat", this::onAddPrompt)
                .label(chat -> chat.getTitle()
                        + "  ·  created " + timestamp(chat.getCreationTime())
                        + "  ·  updated " + timestamp(chat.getLastTimeUpdated()))
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
                .scrollable()
                .search("search")
                .build();

        return skillsList;
    }

    public JPanel buildSkillEditor() {
        skillEditor = new MDFileViewer();
        skillEditor.setTitle("Skill instructions");
        skillEditor.withName("Name", "");
        skillEditor.withDescription("Description", "");
        skillEditor.withTypes("Type", List.of(AISkill.SkillType.values()),
                AISkill.SkillType.MD_SKILL, AISkill.SkillType::getName);
        skillEditor.setValidator(this::validateSkill);
        skillEditor.setOnCommit(this::onSaveSkill);
        skillEditor.setOnCancel(() -> {
            selectedSkill = null;
            skillsCards.show("list");
        });
        return skillEditor;
    }

    private boolean validateSkill(MDFileViewer.MDDocument document) {
        String name = document.getName() != null ? document.getName().trim() : "";
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Give the skill a name before saving.",
                    "Skill", JOptionPane.WARNING_MESSAGE);
            return false;
        }
        return true;
    }

    private void onSaveSkill(MDFileViewer.MDDocument document) {
        AISkill skill = selectedSkill != null ? selectedSkill : new AISkill();
        String oldName = skill.getName();
        String oldDescription = skill.getDescription();
        AISkill.SkillType oldType = skill.getSkillType();
        String oldContent = skill.getContent();
        skill.setName(document.getName().trim());
        skill.setDescription(document.getDescription());
        skill.setSkillType(document.typeAs());
        skill.setContent(document.getMarkdown());

        BackgroundTask.runCatching(this, skillEditor.getSaveButton(), () -> {
            try {
                context.saveSkill(skill);
            } catch (Exception e) {
                skill.setName(oldName);
                skill.setDescription(oldDescription);
                skill.setSkillType(oldType);
                skill.setContent(oldContent);
                SwingUtilities.invokeLater(() -> {
                    skillEditor.markDirty();
                    refreshSkills();
                });
                throw e;
            }
        }, () -> {
            selectedSkill = null;
            refreshSkills();
            skillsCards.show("list");
        });
    }

    private static String deleteConfirm(String name, String noun) {
        String subject = (name == null || name.isBlank()) ? "this " + noun : "'" + name + "'";
        return "Delete " + subject + "? This permanently removes it.";
    }

    private static String timestamp(long millis) {
        if (millis <= 0) return "n/a";
        return ROW_TIMESTAMP.format(Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()));
    }

    public JPanel buildProviderCardsPanel() {
        providerCards.add(buildProviderPanel(), "list");
        providerCards.add(buildAddProvider(), "add");
        providerCards.add(buildCreateProviderKey(), "create");

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
                .addButton(" + Add Provider", this::onAddProvider)
                .label(AIProvider::getName)
                .emptyText("No providers")
                .onEdit(p -> () -> onEditProvider(p))
                .onRemove(p -> () -> onRemoveProvider(p))
                .scrollable()
                .build();

        return providerList;
    }

    public JPanel buildAddProvider() {
        providerAddList = ListSection.of(this::availableKeys)
                .title("Available keys")
                .label(this::keyLabel)
                .emptyText("No keys yet")
                .action(new ListSection.RowAction<>(new IconUtil.PlusIcon(16), "Add to assistant",
                        k -> () -> onSelectAddKey(k)))
                .build();

        JButton newKey = new JButton("New Key", new IconUtil.PlusIcon(16));
        newKey.setToolTipText("Add a provider API key you don't have in NoSneak yet");
        newKey.addActionListener(_ -> providerCards.show("create"));

        return PanelBuilder.detail("Add a key", () -> providerCards.show("list"),
                content -> {
                    content.add(providerAddList, "growx");
                    content.add(newKey, "gaptop 8");
                });
    }

    public JPanel buildCreateProviderKey() {
        JTextField keyLabel = PanelBuilder.textField("e.g. Claude prod");
        JComboBox<String> provider = new JComboBox<>(PROVIDER_DISPLAY);
        JPasswordField secret = new JPasswordField(28);
        secret.putClientProperty("JTextField.placeholderText", "Your API key");
        JTextField baseURL = PanelBuilder.textField("Optional — provider default when empty");
        JButton create = new JButton("Add to assistant", new IconUtil.PlusIcon(16));

        create.addActionListener(_ -> {
            String name = keyLabel.getText().trim();
            String rawKey = new String(secret.getPassword()).trim();
            if (name.isEmpty() || rawKey.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Enter a label and the API key.",
                        "Missing information", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String canonical = PROVIDER_CANONICAL[provider.getSelectedIndex()];
            String url = baseURL.getText().trim();

            BackgroundTask.run(this, create,
                    () -> {
                        APIKey<String> key = context.getCredentials()
                                .addAPIKey(name, "", canonical, url, "", "", rawKey);
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
                        keyLabel.setText("");
                        secret.setText("");
                        baseURL.setText("");
                        provider.setSelectedIndex(0);
                        if (providerList != null) providerList.refresh();
                        if (providerAddList != null) providerAddList.refresh();
                        providerCards.show("list");
                        JOptionPane.showMessageDialog(this,
                                "Key added. It also appears in your NoSneak credentials.");
                    });
        });

        return PanelBuilder.detail("New provider key", () -> providerCards.show("add"), panel -> {
            PanelBuilder.addRow(panel, "Label*", keyLabel);
            PanelBuilder.addRow(panel, "Provider*", provider);
            PanelBuilder.addRow(panel, "API Key*", PanelBuilder.passwordField(secret));
            PanelBuilder.addRow(panel, "Base URL", baseURL);
            panel.add(create, "gaptop 10");
        });
    }

    private static String keyIdentity(APIKey<String> key) {
        return (key instanceof ReferenceIDDAO dao) ? dao.getGUID() : null;
    }

    private List<APIKey<String>> availableKeys() {
        Set<String> enabled = new HashSet<>();
        for (APIKey<String> k : context.getCredentials().enabledAPIKeys()) {
            String id = keyIdentity(k);
            if (id != null) enabled.add(id);
        }
        List<APIKey<String>> out = new ArrayList<>();
        for (APIKey<String> k : context.getCredentials().APIKeys()) {
            String id = keyIdentity(k);
            if (id != null && enabled.contains(id)) continue;
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
                .search("search")
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
            JOptionPane.showMessageDialog(this, "Open a chat first (Chat History > + New Chat)",
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
                BackgroundTask.runCatching(this, null, () -> context.saveChat(sending), null);
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
        BackgroundTask.runCatching(this, null, () -> context.saveChat(sending), null);
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
            Map<AISkill.SkillType, List<AISkill>> byType = groupByType(skills);
            boolean showHeaders = byType.size() > 1;

            for (Map.Entry<AISkill.SkillType, List<AISkill>> group : byType.entrySet()) {
                if (showHeaders) {
                    AISkill.SkillType type = group.getKey();
                    content.add(sectionLabel(type != null ? type.getName() : "other"), "gaptop 6");
                }

                for (AISkill skill : group.getValue()) {
                    content.add(skill.getSkillType() == AISkill.SkillType.PROMPT_SKILL
                            ? promptSkillRow(skill, popup)
                            : attachSkillRow(skill));
                }
            }
        }

        popup.add(content);
        popup.show(attachSkillButton, 0, -popup.getPreferredSize().height);
    }

    private JCheckBox attachSkillRow(AISkill skill) {
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
        return box;
    }

    private JButton promptSkillRow(AISkill skill, JPopupMenu popup) {
        JButton insert = new JButton(skill.getName());
        insert.putClientProperty("JButton.buttonType", "borderless");
        insert.setHorizontalAlignment(SwingConstants.LEFT);
        insert.setFocusable(false);
        insert.setToolTipText(skill.getDescription() != null && !skill.getDescription().isEmpty()
                ? skill.getDescription() + " (inserts into the message)"
                : "Insert into the message");
        insert.addActionListener(_ -> {
            popup.setVisible(false);
            insertIntoComposer(skill.getContent());
        });
        return insert;
    }

    private void insertIntoComposer(String text) {
        if (text == null || text.isBlank()) return;

        String existing = composer.getText();
        if (existing.isBlank()) {
            composer.setText(text);
        } else {
            int caret = Math.min(composer.getCaretPosition(), existing.length());
            String before = existing.substring(0, caret);
            composer.insert(before.endsWith("\n") ? text : "\n\n" + text, caret);
        }

        composer.setCaretPosition(composer.getDocument().getLength());
        composer.requestFocusInWindow();
    }

    private static Map<AISkill.SkillType, List<AISkill>> groupByType(List<AISkill> skills) {
        Map<AISkill.SkillType, List<AISkill>> byType = new LinkedHashMap<>();

        for (AISkill.SkillType type : AISkill.SkillType.values()) {
            List<AISkill> ofType = skills.stream()
                    .filter(s -> s.getSkillType() == type)
                    .sorted(Comparator.comparing(AISkill::getName, Comparator.nullsLast(String::compareToIgnoreCase)))
                    .toList();
            if (!ofType.isEmpty()) byType.put(type, ofType);
        }

        List<AISkill> untyped = skills.stream()
                .filter(s -> s.getSkillType() == null)
                .sorted(Comparator.comparing(AISkill::getName, Comparator.nullsLast(String::compareToIgnoreCase)))
                .toList();
        if (!untyped.isEmpty()) byType.put(null, untyped);

        return byType;
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
        JComponent bubble = chatBubble(response, user, latency, tokens,
                user ? null : () -> onSaveSkillFromResponse(response));
        String cons = user
                ? "wmax 60%, alignx trailing"
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
        int res = JOptionPane.showConfirmDialog(this, deleteConfirm(chat.getTitle(), "chat"),
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
        selectedSkill = null;
        showSkillEditor(null, "Create");
    }

    private void onEditSkill(AISkill skill) {
        if (skill == null) return;
        selectedSkill = skill;
        showSkillEditor(skill, "Save");
    }

    private void showSkillEditor(AISkill skill, String saveText) {
        showSkillEditorFields(skill, saveText);
        skillsCards.show("editor");
    }

    private void onSaveSkillFromResponse(String markdown) {
        if (skillEditor != null && skillEditor.isDirty()) {
            int ok = JOptionPane.showConfirmDialog(this,
                    "Discard the unsaved skill edits and start a new skill from this response?",
                    "Unsaved skill", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (ok != JOptionPane.OK_OPTION) return;
        }
        selectedSkill = null;
        showSkillEditorFields(null, "Create");
        skillEditor.setMarkdown(markdown);
        skillsCards.show("editor");
        skillsButton.doClick();
    }

    private void showSkillEditorFields(AISkill skill, String saveText) {
        skillEditor.setSaveText(saveText);
        skillEditor.setDocumentName(skill != null ? skill.getName() : "");
        skillEditor.setDescription(skill != null ? skill.getDescription() : "");
        skillEditor.setSelectedType(skill != null && skill.getSkillType() != null
                ? skill.getSkillType() : AISkill.SkillType.MD_SKILL);
        skillEditor.setMarkdown(skill != null ? skill.getContent() : "");
    }

    private void onRemoveSkill(AISkill skill) {
        if (skill == null) return;
        int res = JOptionPane.showConfirmDialog(this, deleteConfirm(skill.getName(), "skill"),
                "Delete skill", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null, () -> context.deleteSkill(skill), () -> {
            if (selectedSkill == skill) selectedSkill = null;
            if (pendingSkills.remove(skill)) refreshSkillTooltip();
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
                    context.getProviders().unregister(provider.getName());
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

    private static final String[] NON_CHAT_MODEL_MARKERS = {
            "whisper", "tts", "embedding", "moderation", "dall-e", "davinci", "babbage",
            "audio", "realtime", "image", "transcribe"};

    private static boolean isChatModel(String modelID) {
        if (modelID == null) return false;
        String m = modelID.toLowerCase();
        for (String marker : NON_CHAT_MODEL_MARKERS) {
            if (m.contains(marker)) return false;
        }
        return true;
    }

    private void fillModels(JComboBox<String> box, String providerName) {
        box.removeAllItems();
        AIProvider p = context.getProviders().lookup(providerName);
        if (p == null) return;
        try {
            String[] models = p.getModelCatalog().models();
            if (models != null) for (String m : models) {
                if (isChatModel(m)) box.addItem(m);
            }
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
        if (skillEditor != null) showSkillEditorFields(null, "Create");
    }
}
