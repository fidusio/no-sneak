package io.xlogistx.nosneak.ai.assistant;

import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.ComponentRef;
import io.xlogistx.nosneak.ai.assistant.panels.CapturePanel;
import io.xlogistx.nosneak.ai.assistant.panels.ChatPanel;
import io.xlogistx.nosneak.ai.assistant.panels.JobQueuePanel;
import io.xlogistx.nosneak.ai.assistant.panels.ProvidersPanel;
import io.xlogistx.nosneak.ai.assistant.panels.SkillsPanel;

import javax.swing.*;
import java.awt.*;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
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

    /**
     * The pages. {@link #QUEUE} is a stub and is not offered by the host's navigation. Each page's
     * title is its display name (2026-10-26): the panel shows it at the top of the page and the
     * host's sidebar uses the same words, so one string names a page everywhere. {@link #CHAT} is
     * the list of chats and the open conversation in one page (merged 2026-10-26).
     */
    public enum Page implements GetDisplayName, GetDescription {
        CHAT("Chat", "Your chats with the assistant: open one, or start a new one"),
        QUEUE("Job Queue", "Requests waiting for, or receiving, a reply"),
        SKILLS("Skills", "Instructions the assistant carries into a chat"),
        PROVIDERS("Providers", "Which of your API keys the assistant may use, and their models"),
        CAPTURE("Capture", "Screen areas shot at once, kept for the chat");

        /** The page title (the component's name); the same words as the sidebar's Screen. */
        private final String displayName;
        /** One line on what the page is for. */
        private final String description;

        Page(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }

        @Override
        public String getDescription() {
            return description;
        }

        @Override
        public String getDisplayName() {
            return displayName;
        }
    }

    private final AssistantContext context;
    private final CardStack cardStack = new CardStack();
    /** One ref per page (2026-10-27): the card component, keyed by the constant's name, with its title and description. */
    private final Map<Page, ComponentRef<Page>> pages = new EnumMap<>(Page.class);

    private final ChatPanel chatPanel;
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
        providersPanel = new ProvidersPanel(context);
        skillsPanel = new SkillsPanel(context);
        jobQueuePanel = new JobQueuePanel(context);
        capturePanel = new CapturePanel(context);

        chatPanel.setOnSaveAsSkill(markdown -> {
            if (skillsPanel.startSkillFromResponse(markdown)) showPage(Page.SKILLS);
        });

        providersPanel.setOnProvidersChanged(chatPanel::refreshProviderCombos);
        skillsPanel.setOnSkillRemoved(chatPanel::dropPendingSkill);

        capturePanel.setOnSendToChat(capture -> {
            chatPanel.attachCapture(capture);
            chatPanel.showConversation();
            showPage(Page.CHAT);
        });

        page(Page.CHAT, chatPanel); // pages: the list and the conversation scroll themselves (2026-10-26)
        page(Page.QUEUE, new JScrollPane(jobQueuePanel));
        page(Page.SKILLS, skillsPanel);
        page(Page.PROVIDERS, providersPanel); // pages: their tables scroll themselves (2026-10-26)
        page(Page.CAPTURE, capturePanel);

        add(cardStack.view(), BorderLayout.CENTER);
        cardStack.show(pages.get(Page.CHAT).getName());

        reloadProviders();
    }

    /** Registers a page's card as a ref over its constant; the card's key is the ref's name. */
    private void page(Page page, JComponent card) {
        ComponentRef<Page> ref = new ComponentRef<>(card, page);
        pages.put(page, ref);
        cardStack.add(card, ref.getName());
    }

    /** The page's ref: its card is the component, its title and description the constant's. */
    public ComponentRef<Page> page(Page page) {
        return pages.get(page);
    }

    /** Every page's ref, in {@link Page} order. */
    public Map<Page, ComponentRef<Page>> pages() {
        return Collections.unmodifiableMap(pages);
    }

    /**
     * Shows a page, refreshing its list on the way in: a list only rebuilds from its supplier on
     * refresh(), so a page merely switched back to used to show whatever it held when it was last
     * refreshed — stale message counts and timestamps until the next login. Chat lands on the open
     * conversation, or on the refreshed list of chats when none is open. Providers refreshes
     * the list only, not {@code refreshProviderViews()}, which repopulates the chat editor's
     * provider combo and would reset a selection the editor card is still holding.
     */
    public void showPage(Page page) {
        switch (page) {
            case CHAT -> chatPanel.showCurrent();
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
        cardStack.show(pages.get(page).getName());
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
        chatPanel.refreshHistory();
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
        chatPanel.showConversation();
        showPage(Page.CHAT);
    }

    public void resetPanel() {
        context.resetContext();

        chatPanel.reset(); // the list of chats with it
        skillsPanel.reset();
        providersPanel.reset();
        capturePanel.reset();

        current = Page.CHAT;
        cardStack.show(pages.get(Page.CHAT).getName());
    }
}
