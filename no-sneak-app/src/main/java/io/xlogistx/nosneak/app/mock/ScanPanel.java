package io.xlogistx.nosneak.app.mock;

import io.xlogistx.nosneak.app.mock.utility.AppContext;
import io.xlogistx.nosneak.app.mock.utility.CardStack;
import io.xlogistx.nosneak.app.mock.utility.PanelBuilder;

import javax.swing.*;
import java.awt.*;

public class ScanPanel extends JPanel {
    private final PanelBuilder panelBuilder = new PanelBuilder();
    private final CardStack cardStack = new CardStack();

    public ScanPanel(AppContext ctx) {
        setLayout(new BorderLayout());
        cardStack.add(new JPanel(), "temp");

        add(panelBuilder.buildDefaultSplitPanel(cardStack.view(), new JToggleButton("PLACEHOLDER"), new JToggleButton("PLACEHOLDER")));
    }
}
