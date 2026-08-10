package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.CaptureArea;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.gui.SnapShot;
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

    private final List<BufferedImage> pendingImages = new ArrayList<>();
    private final List<String> pendingImageNames = new ArrayList<>();
    private static final int AREA_LIST_MAX_HEIGHT = 160;
    private static final int COMPOSER_MIN_HEIGHT = 44;
    private static final int COMPOSER_MAX_ROWS = 8;

    private final JFileChooser imageChooser = new JFileChooser();
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
     * Attaches an image to the next message, replacing whatever was attached before.
     */
    public void attachImage(BufferedImage image, String name) {
        if (image == null) return;
        pendingImages.add(image);
        pendingImageNames.add((name == null || name.isBlank()) ? "image" : name);
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

        final List<BufferedImage> images = new ArrayList<>(pendingImages);
        final CaptureArea[] areas = areasToSend();

        String typed = composer.getText().trim();
        if (typed.isEmpty() && images.isEmpty() && areas.length == 0) return;
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
        for (BufferedImage i : images) {
            if (i != null) addImage(i);
        }

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
        if (images.isEmpty() && areas.length == 0) {
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
                    SnapShot[] snaps = (areas.length > 0)
                            ? CaptureSupport.shootAndSave(ctx, window, areas)
                            : new SnapShot[0];
                    UByteArrayInputStream[] streams = new UByteArrayInputStream[images.size() + snaps.length];
                    int i = 0;
                    for (BufferedImage image : images) streams[i++] = CaptureSupport.toStream(image);
                    for (SnapShot snap : snaps) streams[i++] = snap.exportAsInputStream(CaptureSupport.IMAGE_FORMAT);
                    p.asyncImageSend(wire, skill, callback, streams);
                    return snaps;
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> failSend(sending, msg, text, e));
                    return null;
                }
            }, snaps -> {
                if (snaps == null) return;
                for (SnapShot snap : snaps) addImage(snap.getImage());
            });
        }
        BackgroundTask.runCatching(this, null, () -> ctx.saveChat(sending), null);
        pendingSkills.clear();
        clearPendingImages();
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
        JLabel thumb = new JLabel(CaptureSupport.scaledIcon(image, 240, 240));
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

        content.add(sectionLabel("Images for this message"), "gaptop 10");
        for (int i = 0; i < pendingImages.size(); i++)
            content.add(imageRow(pendingImages.get(i), pendingImageNames.get(i)));
        content.add(attachImageRow(popup));

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

    private JCheckBox imageRow(BufferedImage image, String name) {
        JCheckBox box = new JCheckBox(name, true);
        box.setOpaque(false);
        box.setToolTipText(image.getWidth() + "x" + image.getHeight() + ", uncheck to drop it");
        box.addActionListener(_ -> {
            int i = pendingImages.indexOf(image);
            if (i >= 0) {
                pendingImages.remove(i);
                pendingImageNames.remove(i);
            }
            refreshSkillTooltip();
        });
        return box;
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

    private void clearPendingImages() {
        pendingImages.clear();
        pendingImageNames.clear();
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
        if (pendingSkills.isEmpty() && pendingImages.isEmpty() && areas.length == 0) {
            attachSkillButton.setToolTipText("Attach skills, images or capture areas to the next message");
            return;
        }
        StringBuilder names = new StringBuilder();
        for (AISkill s : pendingSkills) {
            if (!names.isEmpty()) names.append(", ");
            names.append(s.getName());
        }
        for (String image : pendingImageNames) {
            if (!names.isEmpty()) names.append(", ");
            names.append(image);
        }
        for (CaptureArea area : areas) {
            if (!names.isEmpty()) names.append(", ");
            names.append(area.getName());
        }
        attachSkillButton.setToolTipText("Attached to the next message: " + names);
    }

    public void reset() {
        sendFullHistory.setSelected(true);
        modelFilterField.setText("");
        pendingSkills.clear();
        tickedAreas.clear();
        clearPendingImages();
        composer.setText("");
        promptCards.show("empty");
    }
}
