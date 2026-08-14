package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.nosneak.ai.assistant.panels.CapturePanel;
import io.xlogistx.nosneak.ai.assistant.panels.ChatHistoryPanel;
import io.xlogistx.nosneak.ai.assistant.panels.ChatPanel;
import io.xlogistx.nosneak.ai.assistant.panels.JobQueuePanel;
import io.xlogistx.nosneak.ai.assistant.panels.ProvidersPanel;
import io.xlogistx.nosneak.ai.assistant.panels.SkillsPanel;

import javax.swing.*;
import java.awt.*;
import java.util.function.BiConsumer;

public class AssistantPanel extends JPanel {

    private final AssistantContext context;
    private final CardStack cardStack = new CardStack();

    private final ChatPanel chatPanel;
    private final ChatHistoryPanel historyPanel;
    private final ProvidersPanel providersPanel;
    private final SkillsPanel skillsPanel;
    private final JobQueuePanel jobQueuePanel;
    private final CapturePanel capturePanel;

    private final JToggleButton chatButton = new JToggleButton("Chat");
    private final JToggleButton historyButton = new JToggleButton("Chat History");
    private final JToggleButton skillsButton = new JToggleButton("Skills");

    public AssistantPanel(AssistantContext context) {
        this.context = context;

        setLayout(new BorderLayout());

        chatPanel = new ChatPanel(context);
        historyPanel = new ChatHistoryPanel(context);
        providersPanel = new ProvidersPanel(context);
        skillsPanel = new SkillsPanel(context);
        jobQueuePanel = new JobQueuePanel(context);
        capturePanel = new CapturePanel(context);

        chatPanel.setOnOpenHistory(historyButton::doClick);
        chatPanel.setOnNewChat(() -> {
            historyButton.doClick();
            historyPanel.startNewChat();
        });
        chatPanel.setOnSaveAsSkill(markdown -> {
            if (skillsPanel.startSkillFromResponse(markdown)) skillsButton.doClick();
        });

        historyPanel.setOnChatOpened(() -> {
            chatPanel.showPrompt();
            cardStack.show("chat");
            chatButton.setSelected(true);
        });

        providersPanel.setOnProvidersChanged(historyPanel::refreshProviderCombos);
        skillsPanel.setOnSkillRemoved(chatPanel::dropPendingSkill);

        capturePanel.setOnSendToChat(capture -> {
            chatPanel.attachCapture(capture);
            chatPanel.showPrompt();
            cardStack.show("chat");
            chatButton.setSelected(true);
        });

        cardStack.add(chatPanel, "chat");
        cardStack.add(new JScrollPane(historyPanel), "history");
        cardStack.add(new JScrollPane(jobQueuePanel), "queue");
        cardStack.add(skillsPanel, "skills");
        cardStack.add(new JScrollPane(providersPanel), "providers");
        cardStack.add(capturePanel, "capture");

        JToggleButton jobQueueButton = new JToggleButton("Job Queue");
        JToggleButton providersButton = new JToggleButton("Providers");
        JToggleButton captureButton = new JToggleButton("Capture");

        // A list only rebuilds from its supplier on refresh(), so a page that is merely switched
        // back to shows whatever it held when it was last refreshed — stale message counts and
        // timestamps until the next login. Refresh on the way in.
        chatButton.addActionListener(_ -> cardStack.show("chat"));
        jobQueueButton.addActionListener(_ -> cardStack.show("queue"));
        historyButton.addActionListener(_ -> {
            refreshHistory();
            cardStack.show("history");
        });
        skillsButton.addActionListener(_ -> {
            refreshSkills();
            cardStack.show("skills");
        });
        providersButton.addActionListener(_ -> {
            // The list only — not refreshProviderViews(), which repopulates the chat editor's
            // provider combo and would reset a selection the editor card is still holding.
            providersPanel.refreshList();
            cardStack.show("providers");
        });
        captureButton.addActionListener(_ -> {
            capturePanel.refreshAreas();
            capturePanel.refreshCaptures();
            cardStack.show("capture");
        });

        chatButton.setSelected(true);

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(),
                chatButton, historyButton, providersButton,
                new JSeparator(),
                skillsButton, jobQueueButton, captureButton));

        reloadProviders();
    }

    public void reloadProviders() {
        providersPanel.reloadProviders();
    }

    public void clearProviders() {
        providersPanel.clearProviders();
        chatPanel.clearModels();
    }

    public void refreshHistory() {
        historyPanel.refreshHistory();
    }

    public void refreshSkills() {
        skillsPanel.refreshSkills();
    }

    /**
     * Offers another destination in the skill editor's "Save as" combo. The handler receives the
     * editor's name and content; what it does with them is the host's business.
     */
    public void addSaveTarget(String label, BiConsumer<String, String> handler) {
        skillsPanel.addSaveTarget(label, handler);
    }

    /**
     * Attaches {@code text} to the next message and shows the Chat page — the way another screen
     * hands content to the assistant (the scanner sends scan reports through here).
     * <p>
     * {@code name} becomes the attachment's visible label, so keep it short: it renders as a chip
     * in the transcript, and an over-long one used to push the conversation off-screen.
     *
     * @throws SecurityException if there is no chat open, or the text is blank — an attachment
     *                           with nowhere to land is otherwise silently dropped. The caller is
     *                           expected to show the message.
     */
    public void sendToChat(String text, String name) {
        chatPanel.attachText(text, name);
        chatPanel.showPrompt();
        cardStack.show("chat");
        chatButton.setSelected(true);
    }

    public void resetPanel() {
        context.resetContext();

        chatPanel.reset();
        historyPanel.reset();
        skillsPanel.reset();
        providersPanel.reset();
        capturePanel.reset();

        cardStack.show("chat");
        chatButton.setSelected(true);
    }
}
