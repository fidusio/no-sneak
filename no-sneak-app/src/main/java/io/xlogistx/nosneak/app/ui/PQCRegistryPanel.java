package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.PanelBuilder;

import javax.swing.*;
import java.awt.*;

public class PQCRegistryPanel extends JPanel {
    private final CardStack cardStack = new CardStack();

    public PQCRegistryPanel(AppContext ctx) {
        setLayout(new BorderLayout());
        cardStack.add(new JPanel(), "temp");

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), new JToggleButton("PLACEHOLDER"), new JToggleButton("PLACEHOLDER")));

    }
}
