package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.gui.ComponentRef;
import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Switches between the application's pages (2026-10-24, Phase 2 of the UI redesign). A page is
 * a {@link Screen}; a {@link Route} says which {@link CardLayout} card hosts it and which
 * section of that card's panel to show. The shell registers one route per screen and listens
 * with {@link #onShow} to keep the sidebar in step. Only ever called on the EDT.
 */
public class Navigator {

    /** Every page the sidebar offers, in sidebar order. */
    public enum Screen implements GetDisplayName, GetDescription {
        SCAN("Scan", "Targets, ports and options; the hosts, services and raw report of the run"),
        SCAN_HISTORY("Scan History", "Every report you ran, kept under your account"),
        PROBES("Probe Library", "The bundled service probes and yours, readable in full"),
        CHAT("Chat", "Your chats with the assistant: open one, or start a new one"),
        CAPTURE("Capture", "Screen areas shot at once, kept for the chat"),
        SKILLS("Skills", "Instructions the assistant carries into a chat"),
        PROVIDERS("Providers", "Which of your API keys the assistant may use, and their models"),
        PROFILE("Profile", "Your name, identifiers and addresses"),
        API_KEYS("API Keys", "Your password and the third-party keys the assistant borrows"),
        SETTINGS("Settings", "The MAC vendor list, and the store's backup and restore"),
        ACL("Access Control", "Subjects, permissions, roles and grants (super-admin only)"),
        ;

        /** What the sidebar, the View menu and the page title show (the component's name). */
        private final String displayName;
        /** One line on what the page is for: the sidebar's and the View menu's tooltip. */
        private final String description;

        Screen(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }

        @Override
        public String getDescription() {
            return description;
        }
        /**
         * Returns the display name of an object which is usually
         * used in the context of name override or for context change.
         *
         * @return display name
         */
        @Override
        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * A screen's route (2026-10-27): the ref over the card that hosts it (the content panel is the
     * ref's component, the screen its source), that card's key on the layout, and the section to
     * show inside the card, may be null.
     */
    public record Route(ComponentRef<Screen> ref, String card, Runnable section) {
    }

    private final CardLayout cards;
    private final JPanel content;
    private final Map<Screen, Route> routes = new EnumMap<>(Screen.class);
    private final Map<JComponent, String> cardKeys = new IdentityHashMap<>();
    private final List<Consumer<Screen>> listeners = new ArrayList<>();
    private Screen current;

    /**
     * @param cards   the layout managing the cards
     * @param content the panel whose cards are switched; {@link #register} adds the cards to it
     */
    public Navigator(CardLayout cards, JPanel content) {
        this.cards = cards;
        this.content = content;
    }

    /**
     * Registers where a screen lives: the panel that hosts it (added to the content host the first
     * time it is seen; several screens share one) and what to run inside it, may be null.
     */
    public void register(Screen screen, JComponent card, Runnable section) {
        String key = cardKeys.get(card);
        if (key == null) {
            key = "card" + cardKeys.size();
            cardKeys.put(card, key);
            content.add(card, key);
        }
        routes.put(screen, new Route(new ComponentRef<>(card, screen), key, section));
    }

    /** The screen's ref: its hosting panel as the component, its title and description the constant's; null when unregistered. */
    public ComponentRef<Screen> ref(Screen screen) {
        Route route = routes.get(screen);
        return route != null ? route.ref() : null;
    }

    /** True when {@code card} is the content host's showing card. */
    public boolean isShowing(JComponent card) {
        return card.getParent() == content && card.isVisible();
    }

    /**
     * Shows the given screen: its card, then its section.
     *
     * @throws IllegalArgumentException when no route was registered for it
     */
    public void show(Screen screen) {
        Route route = routes.get(screen);
        if (route == null) throw new IllegalArgumentException("no route for " + screen);
        cards.show(content, route.card());
        if (route.section() != null) route.section().run();
        current = screen;
        for (Consumer<Screen> l : listeners) l.accept(screen);
    }

    /**
     * Records that a panel moved to {@code screen} on its own (the assistant opening its chat
     * page) and tells the listeners, without running the route again.
     */
    public void sync(Screen screen) {
        if (current == screen) return;
        current = screen;
        for (Consumer<Screen> l : listeners) l.accept(screen);
    }

    /** The screen showing now, or null before the first {@link #show}. */
    public Screen current() {
        return current;
    }

    /** Called after every {@link #show} and {@link #sync}. */
    public void onShow(Consumer<Screen> listener) {
        listeners.add(listener);
    }
}
