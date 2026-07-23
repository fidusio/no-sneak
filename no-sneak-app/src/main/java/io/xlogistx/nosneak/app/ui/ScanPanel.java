package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.PanelBuilder;

import javax.swing.*;
import java.awt.*;

public class ScanPanel extends JPanel {
    private final CardStack cardStack = new CardStack();

    public ScanPanel(AppContext ctx) {
        setLayout(new BorderLayout());
        cardStack.add(buildLocalScanPanel(), "Web");
        cardStack.add(buildWebScanPanel(), "Local");

        JToggleButton webScanButton = new JToggleButton("Web Scan");
        webScanButton.addActionListener(e -> cardStack.show("Web"));
        JToggleButton localScanButton = new JToggleButton("Local Scan");
        localScanButton.addActionListener(e -> cardStack.show("Local"));

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), webScanButton, localScanButton));
    }

    private JPanel buildWebScanPanel() {
        return new JPanel();
    }

    private JPanel buildLocalScanPanel() {
        return new JPanel();
    }
}
