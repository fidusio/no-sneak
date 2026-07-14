package io.xlogistx.nosneak.app.mock;

import io.xlogistx.nosneak.app.mock.utility.AppContext;
import io.xlogistx.nosneak.app.mock.utility.CardStack;
import io.xlogistx.nosneak.app.mock.utility.PanelBuilder;

import javax.swing.*;
import java.awt.*;

public class AIAssistantPanel extends JPanel {

    private final CardStack cardStack = new CardStack();
    private final AppContext ctx;

    public AIAssistantPanel(AppContext ctx) {
        this.ctx = ctx;

        setLayout(new BorderLayout());

        cardStack.add(new JScrollPane(buildChatPanel()), "chat");
        cardStack.add(new JScrollPane(buildHistoryPanel()), "history");
        cardStack.add(new JScrollPane(buildSkillsPanel()), "skills");
        cardStack.add(new JScrollPane(buildProvidersPanel()), "providers");

        JToggleButton chatButton = new JToggleButton("Chat");
        chatButton.addActionListener(_ -> cardStack.show("chat"));

        JToggleButton historyButton = new JToggleButton("History");
        historyButton.addActionListener(_ -> cardStack.show("history"));

        JToggleButton skillsButton = new JToggleButton("Skills");
        skillsButton.addActionListener(_ -> cardStack.show("skills"));

        JToggleButton providersButton = new JToggleButton("Providers");
        providersButton.addActionListener(_ -> cardStack.show("providers"));

        ctx.session().onAuthChange(_ -> {
            // @TODO cleanup
        });

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), chatButton, historyButton, skillsButton, providersButton));
    }

    public JPanel buildChatPanel() {
        return new JPanel();
    }

    public JPanel buildHistoryPanel() {
        return new JPanel();
    }

    public JPanel buildSkillsPanel() {
        return new JPanel();
    }

    public JPanel buildProvidersPanel() {
        return new JPanel();
    }
}
