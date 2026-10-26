package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.CardStack;
import io.xlogistx.nosneak.ai.assistant.panels.CapturePanel;
import io.xlogistx.nosneak.ai.assistant.panels.ChatHistoryPanel;
import io.xlogistx.nosneak.ai.assistant.panels.ChatPanel;
import io.xlogistx.nosneak.ai.assistant.panels.JobQueuePanel;
import io.xlogistx.nosneak.ai.assistant.panels.ProvidersPanel;
import io.xlogistx.nosneak.ai.assistant.panels.SkillsPanel;

import javax.swing.*;
import java.awt.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * The assistant's pages behind one {@link CardStack}, with no navigation column of its own
 * (2026-10-24): the host application's sidebar picks the page through {@link #showPage}, and
 * when a page moves the assistant by itself (a chat opened from history, a capture sent to the
 * chat, {@link #sendToChat}) the host hears about it through {@link #setOnPageShown} and
 * highlights the matching item. Wiring only; the pages live in {@code panels}.
 */
public class AssistantPanel extends JPanel {

    /** The pages. {@link #QUEUE} is a stub and is not offered by the host's navigation. */
    public enum Page {CHAT, HISTORY, QUEUE, SKILLS, PROVIDERS, CAPTURE}

    private final AssistantContext context;
    private final CardStack cardStack = new CardStack();

    private final ChatPanel chatPanel;
    private final ChatHistoryPanel historyPanel;
    private final ProvidersPanel providersPanel;
    private final SkillsPanel skillsPanel;
    private final JobQueuePanel jobQueuePanel;
    private final CapturePanel capturePanel;

    private Consumer<Page> onPageShown = page -> {
    };
    private Page current = Page.CHAT;

    public AssistantPanel(AssistantContext context) {
        this.context = context;

        setLayout(new BorderLayout());

        chatPanel = new ChatPanel(context);
        historyPanel = new ChatHistoryPanel(context);
        providersPanel = new ProvidersPanel(context);
        skillsPanel = new SkillsPanel(context);
        jobQueuePanel = new JobQueuePanel(context);
        capturePanel = new CapturePanel(context);

        chatPanel.setOnOpenHistory(() -> showPage(Page.HISTORY));
        chatPanel.setOnNewChat(() -> {
            showPage(Page.HISTORY);
            historyPanel.startNewChat();
        });
        chatPanel.setOnSaveAsSkill(markdown -> {
            if (skillsPanel.startSkillFromResponse(markdown)) showPage(Page.SKILLS);
        });

        historyPanel.setOnChatOpened(() -> {
            chatPanel.showPrompt();
            showPage(Page.CHAT);
        });

        providersPanel.setOnProvidersChanged(historyPanel::refreshProviderCombos);
        skillsPanel.setOnSkillRemoved(chatPanel::dropPendingSkill);

        capturePanel.setOnSendToChat(capture -> {
            chatPanel.attachCapture(capture);
            chatPanel.showPrompt();
            showPage(Page.CHAT);
        });

        cardStack.add(chatPanel, Page.CHAT.name());
        cardStack.add(new JScrollPane(historyPanel), Page.HISTORY.name());
        cardStack.add(new JScrollPane(jobQueuePanel), Page.QUEUE.name());
        cardStack.add(skillsPanel, Page.SKILLS.name());
        cardStack.add(new JScrollPane(providersPanel), Page.PROVIDERS.name());
        cardStack.add(capturePanel, Page.CAPTURE.name());

        add(cardStack.view(), BorderLayout.CENTER);
        cardStack.show(Page.CHAT.name());

        reloadProviders();
    }

    /**
     * Shows a page, refreshing its list on the way in: a list only rebuilds from its supplier on
     * refresh(), so a page merely switched back to used to show whatever it held when it was last
     * refreshed — stale message counts and timestamps until the next login. Providers refreshes
     * the list only, not {@code refreshProviderViews()}, which repopulates the chat editor's
     * provider combo and would reset a selection the editor card is still holding.
     */
    public void showPage(Page page) {
        switch (page) {
            case HISTORY -> refreshHistory();
            case SKILLS -> refreshSkills();
            case PROVIDERS -> providersPanel.refreshList();
            case CAPTURE -> {
                capturePanel.refreshAreas();
                capturePanel.refreshCaptures();
            }
            default -> {
            }
        }
        current = page;
        cardStack.show(page.name());
        onPageShown.accept(page);
    }

    /** The page showing now. */
    public Page getPage() {
        return current;
    }

    /** Told after every {@link #showPage}, including the ones the assistant triggers itself. */
    public void setOnPageShown(Consumer<Page> listener) {
        onPageShown = listener != null ? listener : page -> {
        };
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
        chatPanel.addSaveTarget(label, handler);   // and a "Save as <label>" button on every reply (2026-10-26)
    }

    /**
     * Attaches {@code text} to the next message and shows the Chat page — the way another screen
     * hands content to the assistant (the scanner sends scan reports through here).
     * <p>
     * {@code name} becomes the attachment's visible label, so keep it short: it renders as a chip
     * in the transcript, and an over-long one used to push the conversation off-screen.
     *
     * @throws org.zoxweb.shared.security.AccessSecurityException if there is no chat open, or the text is blank — an attachment
     *                           with nowhere to land is otherwise silently dropped. The caller is
     *                           expected to show the message.
     */
    public void sendToChat(String text, String name) {
        sendToChat(text, name, null);
    }

    /**
     * {@link #sendToChat(String, String)} plus a request typed into the composer for the subject
     * to review and send (2026-10-26): the scanner's Probe library attaches the probe definition
     * and asks for a probe this way. {@code composerText} null or blank = attach only.
     *
     * @throws org.zoxweb.shared.security.AccessSecurityException as the two-argument form
     */
    public void sendToChat(String text, String name, String composerText) {
        chatPanel.attachText(text, name);
        chatPanel.setComposerText(composerText);
        chatPanel.showPrompt();
        showPage(Page.CHAT);
    }

    public void resetPanel() {
        context.resetContext();

        chatPanel.reset();
        historyPanel.reset();
        skillsPanel.reset();
        providersPanel.reset();
        capturePanel.reset();

        current = Page.CHAT;
        cardStack.show(Page.CHAT.name());
    }
}
