package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AIAPIProvider;
import io.xlogistx.nosneak.ai.assistant.AssistantCallback;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.ModelFilter;
import io.xlogistx.nosneak.ai.assistant.AssistantMDDecoder;
import io.xlogistx.nosneak.ai.assistant.AssistantUtil;
import io.xlogistx.nosneak.ai.model.*;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.server.io.UByteArrayInputStream;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.util.NVEntity;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.*;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import static io.xlogistx.nosneak.ai.assistant.AssistantUtil.chatBubble;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.fillModels;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.fillProviders;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.providerRenderer;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.showErrorDialog;

/**
 * The Chat page (merged with Chat History on 2026-10-26, in the house list look): the list of
 * chats — {@link ChatHistoryPanel}, with its New chat / Edit chat forms — is the page, and the
 * open conversation is a page that replaces it (All chats goes back). The sidebar lands on the
 * conversation when a chat is open, on the list otherwise ({@link #showCurrent()}).
 */
public class ChatPanel extends JPanel {

    private final AssistantContext ctx;

    private Consumer<String> onSaveAsSkill;
    /** The host's save targets (label to handler), one "Save as <label>" button per assistant bubble. */
    private final Map<String, BiConsumer<String, String>> saveTargets = new LinkedHashMap<>();

    /** {@code list} = the chats (and their forms), {@code chat} = the open conversation. */
    private final CardStack chatCards = new CardStack();
    private final ChatHistoryPanel history;
    /** Holds the conversation page, rebuilt per {@link #showConversation()} (the title is the chat's). */
    private final JPanel chatHost = new JPanel(new BorderLayout());
    /** Set when a form (Edit, New chat) was opened from the conversation, so closing it returns there. */
    private boolean returnToConversation;
    /** The conversation page's once-built pieces, re-framed by every {@link #showConversation()}. */
    private JPanel headActions;
    private JPanel options;
    private JPanel surface;

    private JPanel transcript;
    private JScrollPane transcriptScroll;
    private JTextArea composer;

    /** The model combo is its own filter (2026-10-28, gui-audio {@code FilterComboBox}): typing narrows it through {@link #modelMatcher}. */
    private FilterComboBox<String> modelSelector;
    /** The chat's model-filter grammar, applied to what is typed in {@link #modelSelector}. */
    private final ModelFilter modelMatcher = new ModelFilter();
    private JComboBox<String> providerSelector;
    /** True while the provider combo is being set from the chat, so the pick handler stays quiet. */
    private boolean syncingProvider;

    private JButton sendButton;
    /** Empties the composer (2026-10-27): the X inside the input box, shown only while it holds text. */
    private JButton clearButton;
    /** Component name of {@link #clearButton}, for tests. */
    public static final String CLEAR_PROMPT = "clear-prompt";
    private JButton attachSkillButton;
    private final List<AISkill> pendingSkills = new ArrayList<>();

    private final List<AISource> pendingSources = new ArrayList<>();
    /**
     * The pending sources as <b>conditional entries at the end of the transcript</b> — a scan
     * report sent from the scanner shows there in full, as a markdown view, so the subject sees
     * what the next prompt is about before typing it. Each view carries a Delete button; that
     * is the only time a source can be dropped, because once sent it is persisted on the
     * request and becomes part of the chat ({@link #addAttachments(List)} renders the same
     * view, without Delete). The entries live in the transcript's own scroll, never in a
     * panel of their own, so they can never cover the conversation. This list is what is
     * currently in the transcript; rebuilt by {@link #refreshPendingPanel()}, which every
     * pending-state change reaches through {@link #refreshSkillTooltip()}.
     */
    private final List<JComponent> pendingViews = new ArrayList<>();
    /** Height cap of one source view in the transcript. */
    private static final int SOURCE_VIEW_MAX_HEIGHT = 260;
    private static final String SOURCE_VIEW_CONSTRAINT = "growx, wmin 0, wmax 92%, alignx trailing";
    private static final int AREA_LIST_MAX_HEIGHT = 160;
    /**
     * Attachment rows carry a caller-supplied name, so they must be width-capped like the bubbles.
     * Unconstrained, one long name sets the transcript's preferred width past the viewport, and
     * since these rows and the user's bubbles are trailing-aligned they land off-screen — with
     * HORIZONTAL_SCROLLBAR_NEVER there is nothing to scroll back with.
     */
    private static final String ATTACHMENT_CONSTRAINT = "wmin 0, wmax 60%, alignx trailing";
    private static final int CHIP_MAX_CHARS = 48;
    private static final int COMPOSER_MIN_HEIGHT = 44;
    private static final int COMPOSER_MAX_ROWS = 8;

    private final JFileChooser imageChooser = new JFileChooser();
    private final JFileChooser fileChooser = new JFileChooser();
    private final Set<CaptureArea> tickedAreas = Collections.newSetFromMap(new IdentityHashMap<>());

    private final JCheckBox sendFullHistory = new JCheckBox("Send history", false);
    /**
     * When ticked, the fenced code blocks of each new reply are copied to the system clipboard as
     * they arrive, so a generated config or command can be pasted without reaching for the bubble's
     * Copy button. Session-scoped view state: never persisted, cleared by {@link #reset()}.
     */
    private final JCheckBox autoCopyCode = new JCheckBox("Auto-copy code", false);

    public ChatPanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());

        history = new ChatHistoryPanel(ctx);
        history.setOnFormClosed(() -> {
            if (returnToConversation && ctx.currentChat() != null) showConversation();
            else returnToConversation = false;
        });
        buildConversation();

        chatCards.add(history, "list");
        chatCards.add(chatHost, "chat");
        chatCards.show("list");
        add(chatCards.view());

        ctx.onChange("currentChat", _ -> refreshPrompt());
    }

    public void setOnSaveAsSkill(Consumer<String> onSaveAsSkill) {
        this.onSaveAsSkill = onSaveAsSkill;
    }

    /**
     * Offers a host destination on every assistant reply (2026-10-26): the bubble gets a
     * "Save as <label>" button that hands the reply's markdown to {@code handler} as
     * {@code (name = "", content)}. A handler that throws has refused the content; its message
     * is shown and nothing else happens, so the reply stays where it is.
     */
    public void addSaveTarget(String label, BiConsumer<String, String> handler) {
        if (label != null && handler != null) saveTargets.put(label, handler);
    }

    /**
     * Fills the composer with {@code text} (2026-10-26), the way another screen prepares a
     * request for the subject to send: appended at the caret when something is already typed,
     * so nothing the subject wrote is lost. Blank text is ignored.
     */
    public void setComposerText(String text) {
        insertIntoComposer(text);
    }

    /**
     * Stores the image as a capture and attaches a reference to it, so the turn it goes out with
     * can record what was sent.
     */
    public void attachImage(BufferedImage image, String name) {
        if (image == null) return;

        BackgroundTask.run(this, null,
                () -> ctx.saveCapture(CaptureSupport.toCapture(image, name, name)),
                this::attachCapture);
    }

    /**
     * Attaches an already stored capture. The bytes stay in the store; the source only holds its GUID.
     */
    public void attachCapture(AICapture capture) {
        AISource source = SourceSupport.fromCapture(capture);
        if (source == null) return;

        pendingSources.add(source);
        refreshSkillTooltip();
    }

    /**
     * What the sidebar lands on: the open conversation when there is one, else the list of chats,
     * refreshed on the way in.
     */
    public void showCurrent() {
        if (ctx.currentChat() != null) {
            showConversation();
        } else {
            history.refreshHistory();
            chatCards.show("list");
        }
    }

    /**
     * Shows the current chat as a page (EDT-safe): a fresh {@link PagePanel} titled by the chat,
     * its facts line under it, the head actions, the options row and the transcript-and-composer
     * card. The pieces are built once and re-framed here, the way the Skills page re-frames its
     * one editor. With no current chat the list shows instead.
     */
    public void showConversation() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::showConversation);
            return;
        }
        AIChat chat = ctx.currentChat();
        if (chat == null) {
            chatCards.show("list");
            return;
        }
        returnToConversation = false;
        PagePanel page = new PagePanel(ChatHistoryModel.title(chat), history.facts(chat));
        page.action(headActions);
        page.row(options);
        page.card(surface);
        chatHost.removeAll();
        chatHost.add(page, BorderLayout.CENTER);
        chatHost.revalidate();
        chatHost.repaint();
        chatCards.show("chat");
    }

    /** Re-reads the chats into the list (EDT-safe). */
    public void refreshHistory() {
        history.refreshHistory();
    }

    /** Repopulates the provider combos: the New chat / Edit chat forms' and the conversation's. */
    public void refreshProviderCombos() {
        history.refreshProviderCombos();
        syncProviderSelector(ctx.currentChat());
    }

    public void clearModels() {
        if (modelSelector != null) modelSelector.removeAllItems();
        if (providerSelector != null) {
            syncingProvider = true;
            try {
                providerSelector.removeAllItems();
            } finally {
                syncingProvider = false;
            }
        }
    }

    /**
     * Fills the conversation's provider combo and selects the chat's provider (2026-10-27) without
     * running {@link #onProviderPicked()}. A chat bound to a provider that is not linked any more
     * shows no selection, so a stale name cannot sit there looking valid.
     */
    private void syncProviderSelector(AIChat chat) {
        if (providerSelector == null) return;
        syncingProvider = true;
        try {
            fillProviders(ctx, providerSelector);
            AIProvider p = chat != null ? ctx.lookupProvider(chat.getProvider()) : null;
            providerSelector.setSelectedItem(p != null ? p.getID() : null);
        } finally {
            syncingProvider = false;
        }
    }

    /**
     * The conversation's provider combo (2026-10-27, "can I switch between them"): the next
     * message goes to the picked provider, in this chat. The model list refills with that
     * provider's models and lands on its default model (else the first); the chat is saved with
     * the new binding; the facts line under the title follows. The transcript is untouched, and
     * whether the new provider sees it stays the <i>Send history</i> box's business.
     * <p>
     * Whatever was typed to narrow the old provider's list goes with the refill (2026-10-28: the
     * filter lives in the combo now and {@code removeAllItems} clears it), so the new provider's
     * list is never hidden behind a pattern meant for the old one.
     */
    /** The chat's combo holds every discovered model; what shows is the matcher's call, blank text = chat models. */
    private static final java.util.function.Predicate<String> ALL_MODELS = _ -> true;

    private void onProviderPicked() {
        if (syncingProvider) return;
        AIChat chat = ctx.currentChat();
        String ref = (String) providerSelector.getSelectedItem();
        if (chat == null || ref == null || ref.equals(chat.getProvider())) return;
        chat.setProvider(ref);
        fillModels(ctx, modelSelector, ref, ALL_MODELS);
        String preferred = ctx.lookupProvider(ref) instanceof AIAPIProvider api ? api.getConfig().getDefaultModel() : null;
        if (preferred != null && !preferred.isBlank()) modelSelector.setSelectedItem(preferred);
        else if (modelSelector.getItemCount() > 0) modelSelector.setSelectedIndex(0);
        else modelSelector.setSelectedItem(null);
        Object model = modelSelector.getSelectedItem();
        chat.setModel(model == null || model.toString().isBlank() ? null : model.toString());
        BackgroundTask.runCatching(this, null, () -> ctx.saveChat(chat), null);
        SwingUtilities.invokeLater(this::showConversation); // after the combo's event: the page is re-framed
    }

    public void dropPendingSkill(AISkill skill) {
        if (pendingSkills.remove(skill)) refreshSkillTooltip();
    }

    /** The chips above the composer: md skills, attached images, capture areas to shoot on send. */
    private final ChipPanel pendingChips = new ChipPanel();

    private void refreshPendingChips() {
        List<ChipPanel.Chip> chips = new ArrayList<>();
        for (int i = 0; i < pendingSkills.size(); i++) {
            chips.add(new ChipPanel.Chip("skill:" + i, pendingSkills.get(i).getName(), "skill"));
        }
        for (int i = 0; i < pendingSources.size(); i++) {
            AISource source = pendingSources.get(i);
            if (source.isImage()) chips.add(new ChipPanel.Chip("image:" + i, source.getName(), "image"));
        }
        CaptureArea[] areas = areasToSend();
        for (int i = 0; i < areas.length; i++) {
            chips.add(new ChipPanel.Chip("area:" + i, areas[i].getName(), "shot on send"));
        }
        pendingChips.setChips(chips);
        pendingChips.setVisible(!chips.isEmpty());
    }

    private void dropPendingChip(String key) {
        int colon = key.indexOf(':');
        if (colon < 0) return;
        int index;
        try {
            index = Integer.parseInt(key.substring(colon + 1));
        } catch (NumberFormatException e) {
            return;
        }
        switch (key.substring(0, colon)) {
            case "skill" -> {
                if (index < pendingSkills.size()) pendingSkills.remove(index);
            }
            case "image" -> {
                if (index < pendingSources.size()) pendingSources.remove(index);
            }
            case "area" -> {
                CaptureArea[] areas = areasToSend();
                if (index < areas.length) tickedAreas.remove(areas[index]);
            }
            default -> {
            }
        }
        refreshSkillTooltip();
    }

    /**
     * Builds the conversation page's pieces once: the head actions (All chats, Edit, Chat as PDF,
     * New chat — plain toolbar buttons, the page's one primary is Send), the options row (model,
     * filter, Send history, Auto-copy code) and the card (transcript over the composer bar).
     */
    private void buildConversation() {
        transcript = new JPanel(new MigLayout("wrap 1, insets 14, gapy 10", "[grow]"));
        transcript.setBackground(UITokens.surface());

        modelSelector = new FilterComboBox<>();
        modelSelector.setFreeText(true); // a name the list does not offer is kept as typed
        modelSelector.setMatcher((typed, m) -> {
            if (!typed.trim().equals(modelMatcher.getPatterns())) modelMatcher.setPatterns(typed);
            return modelMatcher.accepts(m);
        });
        modelSelector.setToolTipText("The model the next message goes to. Type to narrow the list: gpt-4*, o3, !*preview*  "
                + "(bare words match anywhere, ! excludes, blank hides non-chat models); a name the list does not offer is kept as typed");

        providerSelector = new JComboBox<>();
        providerSelector.setEditable(false);
        providerSelector.setRenderer(providerRenderer(ctx));
        providerSelector.setToolTipText("The assistant the next message goes to. Switching keeps this chat and its transcript; the model list follows");
        providerSelector.addActionListener(_ -> onProviderPicked());

        sendFullHistory.setToolTipText(
                "Checked: each request carries the whole conversation. Unchecked: only the new message is sent.");
        autoCopyCode.setToolTipText(
                "Checked: the code blocks of every new reply are copied to the clipboard as it arrives.");

        JButton allChats = new JButton("All chats", new IconUtil.BackIcon(16));
        allChats.setToolTipText("Back to the list of chats");
        allChats.addActionListener(_ -> {
            history.refreshHistory();
            chatCards.show("list");
        });
        JButton edit = new JButton("Edit", new IconUtil.EditIcon(16));
        edit.setToolTipText("Rename this chat, or change its provider and model");
        edit.addActionListener(_ -> {
            AIChat chat = ctx.currentChat();
            if (chat == null) return;
            returnToConversation = true;
            history.editChat(chat);
            chatCards.show("list");
        });
        JButton chatToPDF = new JButton("Chat as PDF", new IconUtil.PDFIcon(16));
        chatToPDF.setToolTipText("Show the whole chat as a PDF");
        chatToPDF.addActionListener(_ -> showChatAsPDF(chatToPDF));
        JButton newChat = new JButton("New chat", new IconUtil.PlusIcon(16));
        newChat.setToolTipText("Create a new chat");
        newChat.addActionListener(_ -> {
            returnToConversation = true;
            history.startNewChat();
            chatCards.show("list");
        });
        for (JButton b : new JButton[]{allChats, edit, chatToPDF, newChat}) b.putClientProperty("JButton.buttonType", "toolBarButton");
        headActions = new JPanel(new MigLayout("insets 0, gapx 8"));
        headActions.setOpaque(false);
        headActions.add(allChats);
        headActions.add(edit);
        headActions.add(chatToPDF);
        headActions.add(newChat);

        JLabel providerLabel = new JLabel("Provider");
        providerLabel.setForeground(UITokens.muted());
        JLabel modelLabel = new JLabel("Model");
        modelLabel.setForeground(UITokens.muted());
        options = new JPanel(new MigLayout("insets 0, gapx 8", "[][][][]push[][]"));
        options.setOpaque(false);
        options.add(providerLabel);
        options.add(providerSelector, "wmin 160");
        options.add(modelLabel);
        options.add(modelSelector, "wmin 320");
        options.add(sendFullHistory);
        options.add(autoCopyCode);

        transcriptScroll = new JScrollPane(transcript,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        transcriptScroll.setBorder(BorderFactory.createEmptyBorder());
        transcriptScroll.getViewport().setBackground(UITokens.surface());
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

        JScrollPane composerScroll = new JScrollPane(composer, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER) {
            @Override
            public Dimension getPreferredSize() {
                Insets in = getInsets();
                Insets ci = composer.getInsets();
                int row = composer.getFontMetrics(composer.getFont()).getHeight();
                int max = row * COMPOSER_MAX_ROWS + ci.top + ci.bottom + in.top + in.bottom;
                int want = composer.getPreferredSize().height + in.top + in.bottom;
                return new Dimension(0, Math.max(COMPOSER_MIN_HEIGHT, Math.min(max, want)));
            }
        };
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

        JPanel attachButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        attachButtons.setOpaque(false);
        attachButtons.add(attachSkillButton);

        JPanel addSkillHolder = new JPanel(new BorderLayout());
        addSkillHolder.setOpaque(false);
        addSkillHolder.add(attachButtons, BorderLayout.NORTH);

        // the X at the right end of the input box, the + button's twin (2026-10-27)
        clearButton = new JButton(new IconUtil.CancelIcon(16));
        clearButton.setName(CLEAR_PROMPT);
        clearButton.putClientProperty("JButton.buttonType", "toolBarButton");
        clearButton.setFocusable(false);
        clearButton.setMargin(new Insets(0, 0, 0, 0));
        clearButton.setPreferredSize(new Dimension(28, 28));
        clearButton.setToolTipText("Clear the prompt (what is attached stays)");
        clearButton.setVisible(false);
        clearButton.addActionListener(_ -> clearComposer());

        JPanel clearHolder = new JPanel(new BorderLayout());
        clearHolder.setOpaque(false);
        clearHolder.add(clearButton, BorderLayout.NORTH);

        JPanel inputBox = new JPanel(new BorderLayout(4, 0));
        inputBox.setBackground(composer.getBackground());
        inputBox.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")),
                BorderFactory.createEmptyBorder(4, 6, 4, 4)));
        inputBox.add(addSkillHolder, BorderLayout.WEST);
        inputBox.add(composerScroll, BorderLayout.CENTER);
        inputBox.add(clearHolder, BorderLayout.EAST);

        sendButton = UITokens.primary(new JButton("Send"));
        sendButton.addActionListener(_ -> onSend());

        // the card's footer: a line above it, the card's own ground
        JPanel composerBar = new JPanel(new BorderLayout(8, 6));
        composerBar.setBackground(UITokens.surface());
        composerBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UITokens.border()),
                BorderFactory.createEmptyBorder(8, 14, 12, 14)));
        composerBar.add(inputBox, BorderLayout.CENTER);
        composerBar.add(sendButton, BorderLayout.EAST);
        // what goes with the next message, as removable chips inside the composer bar (2026-10-24):
        // skills, attached images, capture areas shot on send. Text sources keep their full view
        // at the end of the transcript, so they are not repeated here. Hidden while empty.
        pendingChips.setEmptyText(null);
        pendingChips.setVisible(false);
        pendingChips.onRemove(this::dropPendingChip);
        composerBar.add(pendingChips, BorderLayout.NORTH);

        composer.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                composerChanged(composerBar);
            }

            public void removeUpdate(DocumentEvent e) {
                composerChanged(composerBar);
            }

            public void changedUpdate(DocumentEvent e) {
                composerChanged(composerBar);
            }
        });

        surface = new JPanel(new BorderLayout());
        surface.setOpaque(false);
        surface.add(transcriptScroll, BorderLayout.CENTER);
        surface.add(composerBar, BorderLayout.SOUTH);
    }

    /** The composer's text changed: the bar grows or shrinks with it, the X shows only while there is text. */
    private void composerChanged(JComponent composerBar) {
        clearButton.setVisible(!composer.getText().isEmpty());
        composerBar.revalidate();
    }

    /** The X in the input box (2026-10-27): drops the typed text only — chips and attachments stay — and keeps the focus in the composer. */
    private void clearComposer() {
        composer.setText("");
        composer.requestFocusInWindow();
    }

    private void refreshPrompt() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshPrompt);
            return;
        }

        AIChat chat = ctx.currentChat();
        syncProviderSelector(chat);
        fillModels(ctx, modelSelector, chat != null ? chat.getProvider() : null, ALL_MODELS);

        transcript.removeAll();
        if (chat != null) {
            modelSelector.setSelectedItem(chat.getModel());
            for (NVEntity e : chat.getMessages().values()) {
                AIMessage m = (AIMessage) e;
                AIRequest req = m.getAIRequest();
                if (req != null && req.getContent() != null) {
                    addMessage(req.getContent(), true, null, null, null, null);
                    addAttachments(req);
                }
                AIResponse res = m.getAIResponse();
                if (res != null && res.getContent() != null)
                    addMessage(res.getContent(), false, history.replyMeta(res), latencyOf(res), inTokensOf(res), outTokensOf(res));
            }
        }
        // removeAll took the conditional entries with it; put the still-pending ones back last
        pendingViews.clear();
        refreshPendingPanel();
        transcript.revalidate();
        transcript.repaint();
        // "currentChat" fires on open / create (a chat), and on reset / delete of the open chat
        // (null): the first shows the conversation, the second the list
        if (chat == null) chatCards.show("list");
        else showConversation();
    }

    /**
     * The header's PDF button (2026-10-07): the whole chat — every stored request and response, in
     * order — rendered to one markdown document and shown through {@link AssistantUtil#showAsPDF},
     * the same path as a single bubble's PDF button. Image attachments are embedded under the
     * turn they went out with; other sources are listed by name. The markdown is built on the
     * background worker because the images come out of the store.
     */
    private void showChatAsPDF(JComponent owner) {
        AIChat chat = ctx.currentChat();
        if (chat == null) {
            JOptionPane.showMessageDialog(this, "Open a chat first (Chat > New chat)", "Chat as PDF", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (chat.getMessages().size() == 0) {
            JOptionPane.showMessageDialog(this, "This chat has no messages yet.", "Chat as PDF", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String title = ChatHistoryModel.title(chat);
        AssistantUtil.showAsPDF(owner, title + " — PDF", () -> chatToMarkdown(ctx, chat, title));
    }

    /**
     * Not for the EDT: image attachments are read back from the store through
     * {@code ctx.getCapture} and embedded as {@code data:image/png;base64} images, which
     * {@code MDToPDF} scales to the text width. A capture that is gone from the store, or a
     * non-image source, is listed by name instead.
     */
    static String chatToMarkdown(AssistantContext ctx, AIChat chat, String title) {
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(title).append("\n\n");
        if (chat.getProvider() != null || chat.getModel() != null) {
            sb.append('*');
            if (chat.getProvider() != null) sb.append(chat.getProvider());
            if (chat.getProvider() != null && chat.getModel() != null) sb.append(" · ");
            if (chat.getModel() != null) sb.append(chat.getModel());
            sb.append("*\n\n");
        }
        for (NVEntity e : chat.getMessages().values()) {
            AIMessage m = (AIMessage) e;
            AIRequest req = m.getAIRequest();
            AIResponse res = m.getAIResponse();
            if (req != null && req.getContent() != null) {
                sb.append("---\n\n### You\n\n").append(req.getContent().trim()).append("\n\n");
                for (NVEntity a : req.getAttachments().values()) {
                    AISource source = (AISource) a;
                    byte[] png = source.isImage() ? captureImage(ctx, source.getCaptureGUID()) : null;
                    if (png != null) {
                        sb.append("![").append(source.getName()).append("](data:image/png;base64,")
                                .append(Base64.getEncoder().encodeToString(png)).append(")\n\n");
                        continue;
                    }
                    if (source.isImage()) continue;
                    // a text source is part of the chat: its content goes in, not just its name
                    sb.append("**Attached: ").append(source.getName()).append("**");
                    String sub = SourceSupport.sublabel(source);
                    if (!sub.isEmpty()) sb.append("  \n*").append(sub).append('*');
                    sb.append("\n\n").append(sourceMarkdown(source)).append("\n\n");
                }
            }
            if (res != null && res.getContent() != null) {
                sb.append("### Assistant");
                String who = ChatHistoryModel.replyMeta(ref -> {
                    AIProvider p = ctx.lookupProvider(ref);
                    return p != null ? p.getName() : null;
                }, res);
                if (who != null) sb.append(" · ").append(who);
                sb.append("\n\n").append(res.getContent().trim()).append("\n\n");
            }
        }
        return sb.toString();
    }

    private static byte[] captureImage(AssistantContext ctx, String guid) {
        if (guid == null) return null;
        AICapture capture = ctx.getCapture(guid);
        return capture != null ? capture.getImage() : null;
    }

    private void onSend() {

        if (sendButton == null || !sendButton.isEnabled()) return;

        final List<AISource> sources = new ArrayList<>(pendingSources);
        final List<AISource> imageSources = sources.stream().filter(AISource::isImage).toList();
        final List<AISource> textSources = sources.stream().filter(s -> !s.isImage()).toList();
        final CaptureArea[] areas = areasToSend();

        String typed = composer.getText().trim();
        if (typed.isEmpty() && sources.isEmpty() && areas.length == 0) return;
        final String text = typed.isEmpty() ? defaultPrompt(imageSources, textSources, areas) : typed;

        AIChat chat = ctx.currentChat();
        if (chat == null) {
            JOptionPane.showMessageDialog(this, "Open a chat first (Chat > New chat)",
                    "Send", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Object sel = modelSelector.getSelectedItem();
        if (sel == null || sel.toString().isBlank()) {
            JOptionPane.showMessageDialog(this, "Pick a model first",
                    "Send", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        AIProvider p = ctx.lookupProvider(chat.getProvider());
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

        for (AISource source : sources) request.addAttachment(source);

        AIMessage msg = new AIMessage(request);
        chat.addMessage(msg);
        // Persist before dispatch: the response callback is the only other save point, so a turn
        // that never gets answered (provider down, logout while in flight) would otherwise vanish.
        BackgroundTask.runCatching(this, null, () -> ctx.saveChat(chat), null);
        // the pending entries become the sent turn: out with the conditional views, in with the
        // message and its attachments as part of the chat
        removePendingViews();
        addMessage(text, true, null, null, null, null);
        addAttachments(sources);

        composer.setText("");
        composer.requestFocusInWindow();

        StringBuilder sb = new StringBuilder();

        if (sendFullHistory.isSelected()) {

            for (NVEntity e : chat.getMessages().values()) {
                AIMessage m = (AIMessage) e;
                AIRequest req = m.getAIRequest();
                AIResponse res = m.getAIResponse();
                if (req != null && req.getContent() != null) {
                    sb.append("Human: ").append(req.getContent()).append("\n\n");
                    // an earlier turn's text attachments are part of the chat and go with it;
                    // the current turn's (m == msg) travel in the source block below instead
                    if (m != msg) {
                        String past = SourceSupport.block(textSourcesOf(req));
                        if (!past.isEmpty()) sb.append(past).append("\n\n");
                    }
                }
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
        String sourceBlock = SourceSupport.block(textSources);
        if (!sourceBlock.isEmpty()) {
            if (!skillSb.isEmpty()) skillSb.append("\n\n");
            skillSb.append(sourceBlock);
        }

        final AIChat sending = chat;
        sendButton.setEnabled(false);
        AssistantCallback callback = new AssistantCallback(ctx, sending, msg, p.getID(),
                resp -> {
                    sendButton.setEnabled(true);
                    if (sending == ctx.currentChat() && resp.getContent() != null && !resp.getContent().isEmpty()) {
                        addMessage(resp.getContent(), false, history.replyMeta(resp), latencyOf(resp), inTokensOf(resp), outTokensOf(resp));
                        if (autoCopyCode.isSelected()) copyCode(resp.getContent());
                    }
                }, err -> {
            sendButton.setEnabled(true);
            BackgroundTask.runCatching(this, null, () -> ctx.saveChat(sending), null);
            if (sending == ctx.currentChat()) {
                refreshPrompt();
                if (composer.getText().isBlank()) composer.setText(text);
            }
            showErrorDialog(this, "Send", "Send failed: " + err.getMessage(), err);
        });

        String skill = skillSb.toString();
        if (imageSources.isEmpty() && areas.length == 0) {
            try {
                p.asyncSend(wire, skill, callback);
            } catch (Exception e) {
                failSend(sending, msg, text, e);
                return;
            }
        } else {
            Window window = SwingUtilities.getWindowAncestor(this);
            BackgroundTask.run(this, null, () -> {
                try {
                    AICapture[] shot = (areas.length > 0)
                            ? CaptureSupport.shootAndSave(ctx, window, areas)
                            : new AICapture[0];

                    List<AISource> shotSources = new ArrayList<>();
                    for (AICapture capture : shot) {
                        AISource source = SourceSupport.fromCapture(capture);
                        if (source != null) shotSources.add(source);
                    }

                    List<UByteArrayInputStream> streams = new ArrayList<>();
                    for (AISource source : imageSources) {
                        UByteArrayInputStream stream = imageStream(source);
                        if (stream != null) streams.add(stream);
                    }
                    for (AICapture capture : shot)
                        if (capture.getImage() != null) streams.add(new UByteArrayInputStream(capture.getImage()));

                    if (streams.isEmpty()) p.asyncSend(wire, skill, callback);
                    else p.asyncImageSend(wire, skill, callback, streams.toArray(new UByteArrayInputStream[0]));

                    return shotSources;
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> failSend(sending, msg, text, e));
                    return null;
                }
            }, shotSources -> {
                if (shotSources == null || shotSources.isEmpty()) return;
                for (AISource source : shotSources) request.addAttachment(source);
                addAttachments(shotSources);
                BackgroundTask.runCatching(this, null, () -> ctx.saveChat(sending), null);
            });
        }
        // No save here: the chat was persisted before dispatch (above), the response is
        // persisted by AssistantCallback, and a capture-carrying send saves once more after the
        // attachments land. A second unconditional save on another worker raced the first for a
        // chat with no GUID yet and inserted a duplicate row.
        pendingSkills.clear();
        clearPendingSources();
    }

    private UByteArrayInputStream imageStream(AISource source) {
        AICapture capture = ctx.getCapture(source.getCaptureGUID());
        return (capture != null && capture.getImage() != null)
                ? new UByteArrayInputStream(capture.getImage())
                : null;
    }

    private static String defaultPrompt(List<AISource> imageSources, List<AISource> textSources, CaptureArea[] areas) {
        if (!imageSources.isEmpty() || areas.length > 0) return "Describe this image.";
        return textSources.size() == 1 ? "Review the attached source." : "Review the attached sources.";
    }

    private void failSend(AIChat sending, AIMessage msg, String text, Exception e) {
        sendButton.setEnabled(true);
        sending.getMessages().remove(msg);
        BackgroundTask.runCatching(this, null, () -> ctx.saveChat(sending), null);
        if (sending == ctx.currentChat()) {
            refreshPrompt();
            if (composer.getText().isBlank()) composer.setText(text);
        }
        showErrorDialog(this, "Send", "Send failed: " + e.getMessage(), e);
    }

    /**
     * Puts the reply's fenced code blocks on the system clipboard, joined by a blank line; a reply
     * with no code block leaves the clipboard untouched. Runs on the EDT (it is called from the
     * send callback's EDT half); a clipboard that is held by another application is not an error
     * worth a dialog, so the failure is swallowed.
     */
    static String codeToCopy(String response) {
        List<String> blocks = AssistantMDDecoder.codeBlocks(response);
        return blocks.isEmpty() ? null : String.join("\n\n", blocks);
    }

    private void copyCode(String response) {
        String code = codeToCopy(response);
        if (code == null) return;
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(code), null);
        } catch (IllegalStateException ignored) {
            // the clipboard is currently unavailable; the bubble's Copy button is still there
        }
    }

    /** @param who the reply's {@code provider · model} line ({@link ChatHistoryModel#replyMeta}); null for a user bubble */
    private void addMessage(String response, boolean user, String who, Integer latency, Integer inTokens, Integer outTokens) {
        Map<String, Runnable> saveAs = null;
        if (!user && !saveTargets.isEmpty()) {
            saveAs = new LinkedHashMap<>();
            for (Map.Entry<String, BiConsumer<String, String>> target : saveTargets.entrySet()) {
                String label = target.getKey();
                BiConsumer<String, String> handler = target.getValue();
                saveAs.put(label, () -> {
                    try {
                        handler.accept("", response);
                    } catch (RuntimeException refused) {
                        JOptionPane.showMessageDialog(this, refused.getMessage(),
                                "Not a valid " + label, JOptionPane.ERROR_MESSAGE);
                    }
                });
            }
        }
        // a user bubble carries a copy icon that puts the prompt back in the composer (2026-10-27)
        JComponent bubble = chatBubble(response, who, user, latency, inTokens, outTokens,
                user ? null : () -> {
                    if (onSaveAsSkill != null) onSaveAsSkill.accept(response);
                }, saveAs,
                user ? () -> insertIntoComposer(response) : null);
        String cons = user
                ? "wmin 0, wmax 60%, alignx trailing"
                : "growx, wmin 0, wmax 92%, alignx leading";
        transcript.add(bubble, cons);
        transcript.revalidate();
        transcript.repaint();

        SwingUtilities.invokeLater(() -> {
            JScrollBar v = transcriptScroll.getVerticalScrollBar();
            v.setValue(v.getMaximum());
        });
    }

    /**
     * Renders what a turn was sent with. Image sources get an empty thumbnail slot up front and the
     * pixels loaded into it off the EDT, so the rows keep their order whatever the store does.
     */
    private void addAttachments(List<AISource> sources) {
        for (AISource source : sources) {
            if (!source.isImage()) {
                // part of the chat now: the same full view as the pending area, without Delete
                transcript.add(sourceView(source, null), SOURCE_VIEW_CONSTRAINT);
                continue;
            }

            JLabel thumb = new JLabel();
            thumb.setBorder(BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")));
            thumb.setToolTipText(source.getName());
            transcript.add(thumb, ATTACHMENT_CONSTRAINT);

            String guid = source.getCaptureGUID();
            BackgroundTask.run(this, null, () -> {
                AICapture capture = ctx.getCapture(guid);
                return (capture != null) ? CaptureSupport.toImage(capture.getThumbnail()) : null;
            }, image -> {
                if (image == null) return;
                thumb.setIcon(CaptureSupport.scaledIcon(image, 240, 240));
                thumb.revalidate();
                thumb.repaint();
            });
        }
        transcript.revalidate();
        transcript.repaint();
    }

    private void addAttachments(AIRequest request) {
        List<AISource> sources = new ArrayList<>();
        for (NVEntity e : request.getAttachments().values()) sources.add((AISource) e);
        if (!sources.isEmpty()) addAttachments(sources);
    }

    /** The non-image sources persisted on a request, in attachment order. */
    static List<AISource> textSourcesOf(AIRequest request) {
        List<AISource> out = new ArrayList<>();
        if (request == null || request.getAttachments() == null) return out;
        for (NVEntity e : request.getAttachments().values()) {
            AISource source = (AISource) e;
            if (!source.isImage()) out.add(source);
        }
        return out;
    }

    private static String ellipsize(String text, int max) {
        if (text == null) return "";
        return text.length() <= max ? text : text.substring(0, max - 1) + "…";
    }

    /**
     * A text source rendered in full: a header line (name, then type · origin · size, muted) over
     * an {@link MDViewerPanel} of the content, height-capped with its own scrollbar so a 50 KB
     * scan report does not swallow the transcript. {@code onDelete} non-null adds a Delete button
     * to the header — only the pending area passes one; in the transcript the source is part of
     * the chat and stays.
     */
    private JComponent sourceView(AISource source, Runnable onDelete) {
        JLabel name = new JLabel(ellipsize(source.getName(), CHIP_MAX_CHARS));
        name.setFont(name.getFont().deriveFont(Font.BOLD));
        name.setToolTipText(source.getName());
        JLabel detail = new JLabel(SourceSupport.sublabel(source));
        detail.setFont(detail.getFont().deriveFont(detail.getFont().getSize2D() - 2f));
        detail.setForeground(UIManager.getColor("Label.disabledForeground"));

        JPanel header = new JPanel(new MigLayout("insets 6 10 2 6, gapx 10", "[][grow][]"));
        header.setOpaque(false);
        header.add(name);
        header.add(detail, "wmin 0");
        if (onDelete != null) {
            JButton delete = GUIUtil.iconButton(new IconUtil.DeleteIcon(16), true);
            delete.setToolTipText("Drop this from the next message");
            delete.setFocusable(false);
            delete.addActionListener(_ -> onDelete.run());
            header.add(delete, "alignx trailing");
        }

        MDViewerPanel viewer = new MDViewerPanel();
        viewer.setMarkdown(sourceMarkdown(source));
        JEditorPane pane = viewer.getEditorPane();
        pane.setOpaque(false);
        pane.setBorder(BorderFactory.createEmptyBorder(0, 10, 8, 10));
        JScrollPane body = new JScrollPane(pane,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER) {
            @Override
            public Dimension getPreferredSize() {
                Dimension d = super.getPreferredSize();
                return new Dimension(d.width, Math.min(d.height, SOURCE_VIEW_MAX_HEIGHT));
            }
        };
        body.setBorder(BorderFactory.createEmptyBorder());
        body.setOpaque(false);
        body.getViewport().setOpaque(false);
        body.getVerticalScrollBar().setUnitIncrement(16);

        JPanel view = new JPanel(new BorderLayout());
        Color bg = UIManager.getColor("Button.background");
        view.setBackground(bg != null ? bg : new Color(0xE6E6E6));
        view.setBorder(BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")));
        view.add(header, BorderLayout.NORTH);
        view.add(body, BorderLayout.CENTER);
        return view;
    }

    /**
     * The markdown shown for a source: JSON (every scan report is one) goes into a {@code json}
     * fence so it renders as code; anything else is shown as the markdown it is.
     */
    static String sourceMarkdown(AISource source) {
        String content = source.getContent();
        if (content == null) return "";
        String trimmed = content.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            return "```json\n" + trimmed + "\n```";
        }
        return content;
    }

    private static Integer latencyOf(AIResponse res) {
        return (res != null && res.getLatency() > 0) ? (int) res.getLatency() : null;
    }

    private static Integer inTokensOf(AIResponse res) {
        return (res != null && res.getInTokens() > 0) ? res.getInTokens() : null;
    }

    private static Integer outTokensOf(AIResponse res) {
        return (res != null && res.getOutTokens() > 0) ? res.getOutTokens() : null;
    }

    private void showAttachPopup() {
        JPopupMenu popup = new JPopupMenu();
        JPanel content = new JPanel(new MigLayout("wrap 1, insets 10 12 10 12, gapy 4", "[grow]"));
        content.setOpaque(false);

        content.add(sectionLabel("Skills for this message"));
        List<AISkill> skills = ctx.getAllSkills();
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

        content.add(sectionLabel("Sources for this message"), "gaptop 10");
        for (AISource source : pendingSources) content.add(sourceRow(source));
        content.add(attachImageRow(popup));
        content.add(attachFileRow(popup));
        content.add(attachURLRow(popup));

        content.add(sectionLabel("Capture"), "gaptop 10");
        content.add(defineAreaRow(popup));
        content.add(areaSection(popup), "growx");

        popup.add(content);
        popup.show(attachSkillButton, 0, -popup.getPreferredSize().height);
    }

    private JComponent areaSection(JPopupMenu popup) {
        CaptureArea[] all = ctx.getCaptureAreaSet().getCaptureAreas();
        if (all.length == 0) {
            JLabel none = new JLabel("No capture areas yet");
            none.setEnabled(false);
            return none;
        }

        JPanel areas = new JPanel(new MigLayout("wrap 1, insets 0, gapy 2", "[grow]"));
        areas.setOpaque(false);

        List<JCheckBox> rowBoxes = new ArrayList<>();
        JCheckBox allBox = new JCheckBox("All areas", areasToSend().length == all.length);
        allBox.setOpaque(false);
        allBox.setToolTipText("Send every capture area with the next message");
        allBox.addActionListener(_ -> {
            boolean on = allBox.isSelected();
            tickedAreas.clear();
            if (on) Collections.addAll(tickedAreas, ctx.getCaptureAreaSet().getCaptureAreas());
            for (JCheckBox box : rowBoxes) box.setSelected(on);
            refreshSkillTooltip();
        });

        for (CaptureArea area : all) {
            JCheckBox box = new JCheckBox(area.getName(), tickedAreas.contains(area));
            box.setOpaque(false);
            box.setToolTipText(CaptureSupport.areaSublabel(area) + ", captured when the message is sent");
            box.addActionListener(_ -> {
                if (box.isSelected()) tickedAreas.add(area);
                else tickedAreas.remove(area);
                allBox.setSelected(rowBoxes.stream().allMatch(AbstractButton::isSelected));
                refreshSkillTooltip();
            });
            rowBoxes.add(box);

            JButton remove = GUIUtil.iconButton(new IconUtil.DeleteIcon(14), true);
            remove.setToolTipText("Remove this capture area");
            remove.setFocusable(false);

            JPanel row = new JPanel(new BorderLayout());
            row.setOpaque(false);
            row.add(box, BorderLayout.CENTER);
            row.add(remove, BorderLayout.EAST);

            remove.addActionListener(_ -> {
                ctx.getCaptureAreaSet().removeCaptureAreas(area);
                tickedAreas.remove(area);
                rowBoxes.remove(box);
                areas.remove(row);
                allBox.setSelected(rowBoxes.stream().allMatch(AbstractButton::isSelected));
                areas.revalidate();
                areas.repaint();
                popup.pack();
                refreshSkillTooltip();
            });
            areas.add(row, "growx");
        }

        JScrollPane areaScroll = new JScrollPane(areas);
        areaScroll.setBorder(BorderFactory.createEmptyBorder());
        areaScroll.getViewport().setOpaque(false);
        areaScroll.setOpaque(false);
        areaScroll.getVerticalScrollBar().setUnitIncrement(16);
        areaScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        areaScroll.setPreferredSize(new Dimension(
                areas.getPreferredSize().width + 16,
                Math.min(areas.getPreferredSize().height + 4, AREA_LIST_MAX_HEIGHT)));

        JPanel section = new JPanel(new MigLayout("wrap 1, insets 0, gapy 2", "[grow]"));
        section.setOpaque(false);
        section.add(allBox);
        section.add(areaScroll, "growx");
        return section;
    }

    private JCheckBox sourceRow(AISource source) {
        JCheckBox box = new JCheckBox(source.getName(), true);
        box.setOpaque(false);
        box.setToolTipText(SourceSupport.sublabel(source) + ", uncheck to drop it");
        box.addActionListener(_ -> {
            pendingSources.remove(source);
            refreshSkillTooltip();
        });
        return box;
    }

    private JButton attachFileRow(JPopupMenu popup) {
        JButton button = new JButton("Attach file");
        button.putClientProperty("JButton.buttonType", "borderless");
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setFocusable(false);
        button.setToolTipText("Send the contents of a text file with this message");
        button.addActionListener(_ -> {
            popup.setVisible(false);
            chooseFile();
        });
        return button;
    }

    private JButton attachURLRow(JPopupMenu popup) {
        JButton button = new JButton("Add URL");
        button.putClientProperty("JButton.buttonType", "borderless");
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setFocusable(false);
        button.setToolTipText("Fetch a page and send its text with this message");
        button.addActionListener(_ -> {
            popup.setVisible(false);
            promptForURL();
        });
        return button;
    }

    private JButton attachImageRow(JPopupMenu popup) {
        JButton button = new JButton("Attach image");
        button.putClientProperty("JButton.buttonType", "borderless");
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setFocusable(false);
        button.setToolTipText("Pick one or more png or jpeg files to send with this message");
        button.addActionListener(_ -> {
            popup.setVisible(false);
            chooseImage();
        });
        return button;
    }

    private JButton defineAreaRow(JPopupMenu popup) {
        JButton button = new JButton("Capture area...", new IconUtil.AreaIcon(14));
        button.putClientProperty("JButton.buttonType", "borderless");
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setFocusable(false);
        button.setToolTipText("Drag out a region and add it to the capture areas");
        button.addActionListener(_ -> {
            popup.setVisible(false);
            Window window = SwingUtilities.getWindowAncestor(this);
            BackgroundTask.run(this, null, () -> CaptureSupport.select(ctx, window), selection -> {
                if (selection == null) return;
                CaptureArea area = new CaptureArea(
                        "Area " + (ctx.getCaptureAreaSet().getCaptureAreas().length + 1),
                        selection.display(), selection.bounds());
                ctx.getCaptureAreaSet().addCaptureAreas(area);
                tickedAreas.add(area);
                refreshSkillTooltip();
            });
        });
        return button;
    }

    private CaptureArea[] areasToSend() {
        List<CaptureArea> out = new ArrayList<>();
        for (CaptureArea area : ctx.getCaptureAreaSet().getCaptureAreas())
            if (tickedAreas.contains(area)) out.add(area);
        return out.toArray(new CaptureArea[0]);
    }

    private void chooseImage() {
        imageChooser.setDialogTitle("Attach image");
        imageChooser.setAcceptAllFileFilterUsed(false);
        imageChooser.setFileFilter(new FileNameExtensionFilter("Images", "png", "jpg", "jpeg", "gif", "bmp"));
        imageChooser.setMultiSelectionEnabled(true);
        if (imageChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        for (File file : imageChooser.getSelectedFiles()) {
            BackgroundTask.run(this, null, () -> ImageIO.read(file), image -> {
                if (image == null) {
                    JOptionPane.showMessageDialog(this, "\"" + file.getName() + "\" is not a readable image.",
                            "Attach image", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                attachImage(image, file.getName());
            });
        }
    }

    private void chooseFile() {
        fileChooser.setDialogTitle("Attach file");
        fileChooser.setMultiSelectionEnabled(true);
        if (fileChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File[] files = fileChooser.getSelectedFiles();
        BackgroundTask.run(this, null, () -> {
            List<AISource> read = new ArrayList<>();
            for (File file : files) {
                if (SourceSupport.isImageFile(file)) {
                    BufferedImage image = ImageIO.read(file);
                    if (image != null)
                        read.add(SourceSupport.fromCapture(
                                ctx.saveCapture(CaptureSupport.toCapture(image, file.getName(), file.getName()))));
                } else {
                    read.add(SourceSupport.fromFile(file));
                }
            }
            return read;
        }, sources -> {
            if (sources == null) return;
            for (AISource source : sources) if (source != null) pendingSources.add(source);
            refreshSkillTooltip();
        });
    }

    private void promptForURL() {
        String url = JOptionPane.showInputDialog(this, "Fetch a page and attach its text", "Add URL",
                JOptionPane.PLAIN_MESSAGE);
        if (url == null || url.isBlank()) return;

        String trimmed = url.trim();
        String target = trimmed.matches("(?i)^https?://.*") ? trimmed : "https://" + trimmed;
        BackgroundTask.run(this, null, () -> SourceSupport.fromURL(target), source -> {
            if (source == null) return;
            pendingSources.add(source);
            refreshSkillTooltip();
        });
    }

    private void clearPendingSources() {
        pendingSources.clear();
        refreshSkillTooltip();
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
        Comparator<AISkill> byName =
                Comparator.comparing(AISkill::getName, Comparator.nullsLast(String::compareToIgnoreCase));
        Map<AISkill.SkillType, List<AISkill>> byType = new LinkedHashMap<>();

        for (AISkill.SkillType type : AISkill.SkillType.values()) {
            List<AISkill> ofType = skills.stream()
                    .filter(s -> s.getSkillType() == type)
                    .sorted(byName)
                    .toList();
            if (!ofType.isEmpty()) byType.put(type, ofType);
        }

        List<AISkill> untyped = skills.stream()
                .filter(s -> s.getSkillType() == null)
                .sorted(byName)
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
        // first, so removing the last pending source clears the area (the early return below
        // used to skip it and the deleted view stayed on screen)
        refreshPendingPanel();
        refreshPendingChips();
        CaptureArea[] areas = areasToSend();
        if (pendingSkills.isEmpty() && pendingSources.isEmpty() && areas.length == 0) {
            attachSkillButton.setToolTipText("Attach skills, sources or capture areas to the next message");
            return;
        }
        StringBuilder names = new StringBuilder();
        for (AISkill s : pendingSkills) {
            if (!names.isEmpty()) names.append(", ");
            names.append(s.getName());
        }
        for (AISource source : pendingSources) {
            if (!names.isEmpty()) names.append(", ");
            names.append(source.getName());
        }
        for (CaptureArea area : areas) {
            if (!names.isEmpty()) names.append(", ");
            names.append(area.getName());
        }
        attachSkillButton.setToolTipText("Attached to the next message: " + names);
    }

    /**
     * Rebuilds the conditional entries at the end of the transcript: one full
     * {@link #sourceView} per pending text source, each with Delete. Images stay in the
     * {@code +} popup (they are shown as thumbnails once sent). Scrolls to the bottom so a
     * freshly attached report is in view.
     */
    private void refreshPendingPanel() {
        if (transcript == null) return;
        removePendingViews();
        for (AISource source : new ArrayList<>(pendingSources)) {
            if (source.isImage()) continue;
            JComponent view = sourceView(source, () -> {
                pendingSources.remove(source);
                refreshSkillTooltip();
            });
            transcript.add(view, SOURCE_VIEW_CONSTRAINT);
            pendingViews.add(view);
        }
        transcript.revalidate();
        transcript.repaint();
        if (!pendingViews.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                JScrollBar v = transcriptScroll.getVerticalScrollBar();
                v.setValue(v.getMaximum());
            });
        }
    }

    /** Takes the conditional entries out of the transcript; the pending sources themselves stay. */
    private void removePendingViews() {
        for (JComponent view : pendingViews) transcript.remove(view);
        pendingViews.clear();
    }

    public void attachText(String text, String name) {
        if (text == null || text.isBlank())
            throw new AccessSecurityException("There is nothing to send.");
        if (ctx.currentChat() == null)
            throw new AccessSecurityException("Open a chat first (Chat > New chat)");
        pendingSources.add(SourceSupport.fromText(text, name));
        refreshSkillTooltip();
        composer.requestFocusInWindow();
    }

    public void reset() {
        sendFullHistory.setSelected(false);
        autoCopyCode.setSelected(false);
        pendingSkills.clear();
        tickedAreas.clear();
        clearPendingSources();
        composer.setText("");
        history.reset();
        returnToConversation = false;
        chatCards.show("list");
    }
}
