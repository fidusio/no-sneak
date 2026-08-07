package io.xlogistx.nosneak.app.ui.utility;

import javax.swing.*;
import java.awt.*;

/**
 * Switches between the app's top-level screens by flipping a {@link CardLayout}.
 * Each card is keyed by a {@link Screen} name.
 */
public class Navigator {
    /**
     * The top-level screens. {@code REGISTER} is currently unused (register is a mode of LOGIN).
     */
    public enum Screen {LOGIN, REGISTER, MAIN, SCAN, SUBJECT, MANAGER, ASSISTANT}

    private final CardLayout cards;
    private final JPanel content;

    /**
     * @param cards   the layout managing the screen cards
     * @param content the panel whose cards are switched
     */
    public Navigator(CardLayout cards, JPanel content) {
        this.cards = cards;
        this.content = content;
    }

    /**
     * Shows the given screen.
     *
     * @param s the screen to display
     */
    public void show(Screen s) {
        cards.show(content, s.name());
    }
}
