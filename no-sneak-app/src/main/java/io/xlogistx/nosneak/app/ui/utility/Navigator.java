package io.xlogistx.nosneak.app.ui.utility;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.EnumMap;
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
    public enum Screen {
        SCAN_NEW, SCAN_HISTORY, PROBES,
        CHAT, CHATS, CAPTURE, SKILLS, PROVIDERS,
        PROFILE, API_KEYS, SETTINGS,
        ACL
    }

    /** @param card the card name on the content host; @param section shows the page inside that card, may be null */
    public record Route(String card, Runnable section) {
    }

    private final CardLayout cards;
    private final JPanel content;
    private final Map<Screen, Route> routes = new EnumMap<>(Screen.class);
    private final List<Consumer<Screen>> listeners = new ArrayList<>();
    private Screen current;

    /**
     * @param cards   the layout managing the cards
     * @param content the panel whose cards are switched
     */
    public Navigator(CardLayout cards, JPanel content) {
        this.cards = cards;
        this.content = content;
    }

    /** Registers where a screen lives. */
    public void register(Screen screen, String card, Runnable section) {
        routes.put(screen, new Route(card, section));
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
