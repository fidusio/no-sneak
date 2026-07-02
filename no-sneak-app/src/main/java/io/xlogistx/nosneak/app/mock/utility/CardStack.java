package io.xlogistx.nosneak.app.mock.utility;

import javax.swing.*;
import java.awt.*;

/**
 * A small {@link CardLayout} wrapper for switching sections <em>within</em> a panel
 * (distinct from the top-level {@link Navigator}). Add cards by name, then show one.
 */
public class CardStack {
    private final CardLayout cards = new CardLayout();
    private final JPanel content = new JPanel(cards);

    /**
     * @return the panel hosting the cards; add this to your layout.
     */
    public JComponent view() {
        return content;
    }

    /**
     * Registers a card under the given name.
     *
     * @param c    the component to show as a card
     * @param name the key used to show it later
     */
    public void add(Component c, String name) {
        content.add(c, name);
    }

    /**
     * Shows the card registered under the given name.
     *
     * @param name the card key
     */
    public void show(String name) {
        cards.show(content, name);
    }
}
