package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.PanelBuilder;

import javax.swing.*;
import java.awt.*;

/**
 * The {@code MAIN} screen — a placeholder, and honestly so.
 * <p>
 * It renders two "PLACEHOLDER" toggles over an empty card. Earlier iterations showed a file tree
 * beside a "Public Key / Documents" table, which suggested some kind of PQC file-sharing registry,
 * but <b>no specification for that was ever settled</b> — the layout was a UX sketch, not a design.
 * Treat any structure you find here as unowned: if this screen gets built, it starts from a
 * product decision, not from reverse-engineering these components.
 * <p>
 * It is still registered as a card and reachable from <i>View &gt; PQC file sharing</i>.
 */
public class PQCRegistryPanel extends JPanel {
    private final CardStack cardStack = new CardStack();

    public PQCRegistryPanel(AppContext ctx) {
        setLayout(new BorderLayout());
        cardStack.add(new JPanel(), "temp");

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), new JToggleButton("PLACEHOLDER"), new JToggleButton("PLACEHOLDER")));

    }
}
