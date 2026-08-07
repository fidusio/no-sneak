package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AssistantCallback;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.CaptureArea;
import io.xlogistx.nosneak.ai.model.*;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.util.NVEntity;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    private JButton sendButton;
    private JButton attachSkillButton;
    private final List<AISkill> pendingSkills = new ArrayList<>();

    private BufferedImage pendingImage;
    private String pendingImageName;
    private final JFileChooser imageChooser = new JFileChooser();
    private JButton captureButton;

    private final JCheckBox sendFullHistory = new JCheckBox("Send history", true);

    public ChatPanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());

        promptCards.add(buildEmptyChat(), "empty");
        promptCards.add(buildPromptPanel(), "prompt");

        promptCards.show("empty");
        add(promptCards.view());

        ctx.onChange("currentChat", e -> refreshPrompt());
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
     * Attaches an image to the next message, replacing whatever was attached before.
     */
    public void attachImage(BufferedImage image, String name) {
        if (image == null) return;
        pendingImage = image;
        pendingImageName = (name == null || name.isBlank()) ? "image" : name;
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

        captureButton = new JButton(new IconUtil.CameraIcon(16));
        captureButton.putClientProperty("JButton.buttonType", "toolBarButton");
        captureButton.setFocusable(false);
        captureButton.setMargin(new Insets(0, 0, 0, 0));
        captureButton.setPreferredSize(new Dimension(28, 28));
        captureButton.addActionListener(_ -> onCaptureButton());
        refreshCaptureTooltip();

        JPanel attachButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        attachButtons.setOpaque(false);
        attachButtons.add(attachSkillButton);
        attachButtons.add(captureButton);

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

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(titlePanel, BorderLayout.NORTH);
        panel.add(transcriptScroll, BorderLayout.CENTER);
        panel.add(composerBar, BorderLayout.SOUTH);
        return panel;
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

        final BufferedImage image = pendingImage;

        String typed = composer.getText().trim();
        if (typed.isEmpty() && image == null) return;
        final String text = typed.isEmpty() ? "Describe this image." : typed;

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

        AIMessage msg = new AIMessage(request);
        chat.addMessage(msg);
        addMessage(text, true, null, null);
        if (image != null) addImage(image);
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

            if (image != null) p.asyncImageSend(wire, skillSb.toString(), callback, image);
            else p.asyncSend(wire, skillSb.toString(), callback);
        } catch (Exception e) {
            sendButton.setEnabled(true);
            sending.getMessages().remove(msg);
            if (sending == ctx.currentChat()) {
                refreshPrompt();
                if (composer.getText().isBlank()) composer.setText(text);
            }
            JOptionPane.showMessageDialog(this, "Send failed: " + e.getMessage(),
                    "Send", JOptionPane.ERROR_MESSAGE);
            return;
        }
        BackgroundTask.runCatching(this, null, () -> ctx.saveChat(sending), null);
        pendingSkills.clear();
        clearPendingImage();
    }

    private void addMessage(String response, boolean user, Integer latency, Integer tokens) {
        JComponent bubble = chatBubble(response, user, latency, tokens,
                user ? null : () -> {
                    if (onSaveAsSkill != null) onSaveAsSkill.accept(response);
                });
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

    /**
     * Display only: the image is not part of the stored message, so it leaves the transcript on the
     * next refreshPrompt().
     */
    private void addImage(BufferedImage image) {
        int max = 240;
        double scale = Math.min(1.0, (double) max / Math.max(image.getWidth(), image.getHeight()));
        Image scaled = image.getScaledInstance(
                Math.max(1, (int) (image.getWidth() * scale)),
                Math.max(1, (int) (image.getHeight() * scale)), Image.SCALE_SMOOTH);

        JLabel thumb = new JLabel(new ImageIcon(scaled));
        thumb.setBorder(BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")));
        thumb.setToolTipText(image.getWidth() + "x" + image.getHeight());
        transcript.add(thumb, "alignx trailing");
        transcript.revalidate();
        transcript.repaint();
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

        content.add(sectionLabel("Image for this message"), "gaptop 10");
        content.add(imageRow(popup));

        content.add(sectionLabel("Capture"), "gaptop 10");
        content.add(captureOnceRow(popup));
        for (CaptureArea area : ctx.getCaptureAreas())
            content.add(areaRow(area, popup));

        popup.add(content);
        popup.show(attachSkillButton, 0, -popup.getPreferredSize().height);
    }

    private JButton imageRow(JPopupMenu popup) {
        boolean attached = (pendingImage != null);
        JButton button = new JButton(attached ? "Remove " + pendingImageName : "Attach image");
        button.putClientProperty("JButton.buttonType", "borderless");
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setFocusable(false);
        button.setToolTipText(attached
                ? "Send this message without the image"
                : "Pick a png or jpeg to send with this message");
        button.addActionListener(_ -> {
            popup.setVisible(false);
            if (attached) clearPendingImage();
            else chooseImage();
        });
        return button;
    }

    /**
     * The one-click path: re-shoots the area used last, or falls back to a drag when none is
     * defined. It attaches rather than sends, because a saved rectangle points at whatever moved
     * into that space since it was defined.
     */
    private void onCaptureButton() {
        CaptureArea area = defaultArea();
        if (area == null) capture(null, null, false);
        else shootArea(area, false);
    }

    private void shootArea(CaptureArea area, boolean sendNow) {
        area.setLastUsed(System.currentTimeMillis());
        refreshCaptureTooltip();
        capture(area.getBounds(), area.getName(), sendNow);
    }

    private CaptureArea defaultArea() {
        CaptureArea latest = null;
        for (CaptureArea area : ctx.getCaptureAreas())
            if (latest == null || area.getLastUsed() >= latest.getLastUsed()) latest = area;
        return latest;
    }

    private void refreshCaptureTooltip() {
        if (captureButton == null) return;
        CaptureArea area = defaultArea();
        captureButton.setToolTipText(area == null
                ? "Drag out a region and attach it to this message"
                : "Capture " + area.getName() + " and attach it");
    }

    private JButton captureOnceRow(JPopupMenu popup) {
        JButton button = new JButton("Capture area...", new IconUtil.AreaIcon(14));
        button.putClientProperty("JButton.buttonType", "borderless");
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setFocusable(false);
        button.setToolTipText("Drag out a region and attach it to this message");
        button.addActionListener(_ -> {
            popup.setVisible(false);
            capture(null, null, false);
        });
        return button;
    }

    private JPanel areaRow(CaptureArea area, JPopupMenu popup) {
        JButton attach = new JButton(area.getName(), new IconUtil.CameraIcon(14));
        attach.putClientProperty("JButton.buttonType", "borderless");
        attach.setHorizontalAlignment(SwingConstants.LEFT);
        attach.setFocusable(false);
        attach.setToolTipText("Capture " + CaptureSupport.region(area.getBounds()) + " and attach it");
        attach.addActionListener(_ -> {
            popup.setVisible(false);
            shootArea(area, false);
        });

        JButton send = GUIUtil.iconButton(new IconUtil.NextIcon(14), true);
        send.setToolTipText("Capture and send straight away");
        send.setFocusable(false);
        send.addActionListener(_ -> {
            popup.setVisible(false);
            shootArea(area, true);
        });

        JPanel row = new JPanel(new BorderLayout());
        row.setOpaque(false);
        row.add(attach, BorderLayout.CENTER);
        row.add(send, BorderLayout.EAST);
        return row;
    }

    /**
     * Shoots the region, saves it, and attaches it. The saved row is what makes the image
     * recoverable later; the attached BufferedImage is what goes on the wire.
     */
    private void capture(Rectangle bounds, String areaName, boolean sendNow) {
        Window window = SwingUtilities.getWindowAncestor(this);
        String name = (areaName != null ? areaName : "Capture")
                + " " + PanelSupport.timestamp(System.currentTimeMillis());

        BackgroundTask.run(this, captureButton, () -> {
            BufferedImage shot = CaptureSupport.shoot(window, bounds);
            if (shot == null) return null;
            ctx.saveCapture(CaptureSupport.toCapture(shot, name, areaName));
            return shot;
        }, shot -> {
            if (shot == null) {
                JOptionPane.showMessageDialog(this, "Nothing was selected. Drag out an area to capture it.",
                        "Capture", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            attachImage(shot, name);
            if (sendNow) onSend();
        });
    }

    private void chooseImage() {
        imageChooser.setDialogTitle("Attach image");
        imageChooser.setAcceptAllFileFilterUsed(false);
        imageChooser.setFileFilter(new FileNameExtensionFilter("Images", "png", "jpg", "jpeg", "gif", "bmp"));
        if (imageChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File file = imageChooser.getSelectedFile();
        BackgroundTask.run(this, null, () -> ImageIO.read(file), image -> {
            if (image == null) {
                JOptionPane.showMessageDialog(this, "That file is not a readable image.",
                        "Attach image", JOptionPane.WARNING_MESSAGE);
                return;
            }
            pendingImage = image;
            pendingImageName = file.getName();
            refreshSkillTooltip();
        });
    }

    private void clearPendingImage() {
        pendingImage = null;
        pendingImageName = null;
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
        if (pendingSkills.isEmpty() && pendingImage == null) {
            attachSkillButton.setToolTipText("Attach skills or an image to the next message");
            return;
        }
        StringBuilder names = new StringBuilder();
        for (AISkill s : pendingSkills) {
            if (!names.isEmpty()) names.append(", ");
            names.append(s.getName());
        }
        if (pendingImage != null) {
            if (!names.isEmpty()) names.append(", ");
            names.append(pendingImageName);
        }
        attachSkillButton.setToolTipText("Attached to the next message: " + names);
    }

    public void reset() {
        sendFullHistory.setSelected(true);
        pendingSkills.clear();
        clearPendingImage();
        refreshCaptureTooltip();
        composer.setText("");
        promptCards.show("empty");
    }
}
