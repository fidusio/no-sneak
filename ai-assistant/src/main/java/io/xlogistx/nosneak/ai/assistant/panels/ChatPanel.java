package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.CaptureArea;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AssistantCallback;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.model.*;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.server.io.UByteArrayInputStream;
import org.zoxweb.shared.util.NVEntity;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import static io.xlogistx.nosneak.ai.assistant.AssistantUtil.chatBubble;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.fillModels;

public class ChatPanel extends JPanel {

    private final AssistantContext ctx;

    private Runnable onNewChat;
    private Runnable onOpenHistory;
    private Consumer<String> onSaveAsSkill;

    private final CardStack promptCards = new CardStack();

    private JPanel transcript;
    private JScrollPane transcriptScroll;
    private JTextArea composer;

    private JLabel chatTitle;
    private JComboBox<String> modelSelector;
    private JTextField modelFilterField;

    private JButton sendButton;
    private JButton attachSkillButton;
    private final List<AISkill> pendingSkills = new ArrayList<>();

    private final List<AISource> pendingSources = new ArrayList<>();
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

    private final JCheckBox sendFullHistory = new JCheckBox("Send history", true);

    public ChatPanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());

        promptCards.add(buildEmptyChat(), "empty");
        promptCards.add(buildPromptPanel(), "prompt");

        promptCards.show("empty");
        add(promptCards.view());

        ctx.onChange("currentChat", _ -> refreshPrompt());
    }

    public void setOnNewChat(Runnable onNewChat) {
        this.onNewChat = onNewChat;
    }

    public void setOnOpenHistory(Runnable onOpenHistory) {
        this.onOpenHistory = onOpenHistory;
    }

    public void setOnSaveAsSkill(Consumer<String> onSaveAsSkill) {
        this.onSaveAsSkill = onSaveAsSkill;
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

    public void showPrompt() {
        promptCards.show("prompt");
    }

    public void clearModels() {
        if (modelSelector != null) modelSelector.removeAllItems();
    }

    public void dropPendingSkill(AISkill skill) {
        if (pendingSkills.remove(skill)) refreshSkillTooltip();
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
        openHistory.addActionListener(_ -> {
            if (onOpenHistory != null) onOpenHistory.run();
        });

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
        if (onNewChat != null) onNewChat.run();
    }

    public JPanel buildPromptPanel() {
        transcript = new JPanel(new MigLayout("wrap 1, insets 14, gapy 10", "[grow]"));

        AIChat chat = ctx.currentChat();
        String titleText = (chat != null && chat.getTitle() != null) ? chat.getTitle() : "Default chat";
        chatTitle = PanelBuilder.title(titleText);

        modelSelector = new JComboBox<>();
        modelSelector.setEditable(true);

        modelFilterField = PanelBuilder.textField("Filter models", 12);
        modelFilterField.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        modelFilterField.setToolTipText(
                "Narrow the model list: gpt-4*, o3, !*preview*  (bare words match anywhere, ! excludes, blank hides non-chat models)");
        modelFilterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                applyModelFilter();
            }

            public void removeUpdate(DocumentEvent e) {
                applyModelFilter();
            }

            public void changedUpdate(DocumentEvent e) {
                applyModelFilter();
            }
        });

        sendFullHistory.setToolTipText(
                "Checked: each request carries the whole conversation. Unchecked: only the new message is sent.");

        JButton newChat = new JButton("New Chat", new IconUtil.PlusIcon(16));
        newChat.setToolTipText("Create a new chat");
        newChat.addActionListener(_ -> openChatCreator());

        JPanel titlePanel = new JPanel(new FlowLayout());
        titlePanel.add(chatTitle);
        titlePanel.add(modelSelector);
        titlePanel.add(modelFilterField);
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

        composer.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                composerBar.revalidate();
            }

            public void removeUpdate(DocumentEvent e) {
                composerBar.revalidate();
            }

            public void changedUpdate(DocumentEvent e) {
                composerBar.revalidate();
            }
        });

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(titlePanel, BorderLayout.NORTH);
        panel.add(transcriptScroll, BorderLayout.CENTER);
        panel.add(composerBar, BorderLayout.SOUTH);
        return panel;
    }

    private void applyModelFilter() {
        Object selected = modelSelector.getSelectedItem();
        ctx.setModelFilter(modelFilterField.getText());

        AIChat chat = ctx.currentChat();
        fillModels(ctx, modelSelector, chat != null ? chat.getProvider() : null);
        if (selected != null) modelSelector.setSelectedItem(selected);
    }

    private void refreshPrompt() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshPrompt);
            return;
        }

        AIChat chat = ctx.currentChat();
        promptCards.show(chat == null ? "empty" : "prompt");
        chatTitle.setText(chat != null && chat.getTitle() != null ? chat.getTitle() : "Default chat");
        fillModels(ctx, modelSelector, chat != null ? chat.getProvider() : null);

        transcript.removeAll();
        if (chat != null) {
            modelSelector.setSelectedItem(chat.getModel());
            for (NVEntity e : chat.getMessages().values()) {
                AIMessage m = (AIMessage) e;
                AIRequest req = m.getAIRequest();
                if (req != null && req.getContent() != null) {
                    addMessage(req.getContent(), true, null, null);
                    addAttachments(req);
                }
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

        final List<AISource> sources = new ArrayList<>(pendingSources);
        final List<AISource> imageSources = sources.stream().filter(AISource::isImage).toList();
        final List<AISource> textSources = sources.stream().filter(s -> !s.isImage()).toList();
        final CaptureArea[] areas = areasToSend();

        String typed = composer.getText().trim();
        if (typed.isEmpty() && sources.isEmpty() && areas.length == 0) return;
        final String text = typed.isEmpty() ? defaultPrompt(imageSources, textSources, areas) : typed;

        AIChat chat = ctx.currentChat();
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
        addMessage(text, true, null, null);
        addAttachments(sources);

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
        String sourceBlock = SourceSupport.block(textSources);
        if (!sourceBlock.isEmpty()) {
            if (!skillSb.isEmpty()) skillSb.append("\n\n");
            skillSb.append(sourceBlock);
        }

        final AIChat sending = chat;
        sendButton.setEnabled(false);
        AssistantCallback callback = new AssistantCallback(ctx, sending, msg,
                resp -> {
                    sendButton.setEnabled(true);
                    if (sending == ctx.currentChat() && resp.getContent() != null && !resp.getContent().isEmpty())
                        addMessage(resp.getContent(), false, latencyOf(resp), tokensOf(resp));
                }, err -> {
            sendButton.setEnabled(true);
            BackgroundTask.runCatching(this, null, () -> ctx.saveChat(sending), null);
            if (sending == ctx.currentChat()) {
                refreshPrompt();
                if (composer.getText().isBlank()) composer.setText(text);
            }
            JOptionPane.showMessageDialog(this, "Send failed: " + err.getMessage(), "Send", JOptionPane.ERROR_MESSAGE);
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
        BackgroundTask.runCatching(this, null, () -> ctx.saveChat(sending), null);
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
        JOptionPane.showMessageDialog(this, "Send failed: " + e.getMessage(),
                "Send", JOptionPane.ERROR_MESSAGE);
    }

    private void addMessage(String response, boolean user, Integer latency, Integer tokens) {
        JComponent bubble = chatBubble(response, user, latency, tokens,
                user ? null : () -> {
                    if (onSaveAsSkill != null) onSaveAsSkill.accept(response);
                });
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
                transcript.add(sourceChip(source), ATTACHMENT_CONSTRAINT);
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

    private static String ellipsize(String text, int max) {
        if (text == null) return "";
        return text.length() <= max ? text : text.substring(0, max - 1) + "…";
    }

    private JComponent sourceChip(AISource source) {
        JLabel chip = new JLabel(ellipsize(source.getName(), CHIP_MAX_CHARS));
        chip.setToolTipText(source.getName() + " — " + SourceSupport.sublabel(source));
        chip.setForeground(UIManager.getColor("Label.disabledForeground"));
        chip.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")),
                BorderFactory.createEmptyBorder(2, 6, 2, 6)));
        return chip;
    }

    private static Integer latencyOf(AIResponse res) {
        return (res != null && res.getLatency() > 0) ? (int) res.getLatency() : null;
    }

    private static Integer tokensOf(AIResponse res) {
        return (res != null && res.getTokens() > 0) ? res.getTokens() : null;
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
            BackgroundTask.run(this, null, () -> CaptureSupport.select(window), selection -> {
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

    public void attachText(String text, String name) {
        if (text == null || text.isBlank())
            throw new SecurityException("There is nothing to send.");
        if (ctx.currentChat() == null)
            throw new SecurityException("Open a chat first (Chat History > + New Chat)");
        pendingSources.add(SourceSupport.fromText(text, name));
        refreshSkillTooltip();
    }

    public void reset() {
        sendFullHistory.setSelected(true);
        modelFilterField.setText("");
        pendingSkills.clear();
        tickedAreas.clear();
        clearPendingSources();
        composer.setText("");
        promptCards.show("empty");
    }
}
