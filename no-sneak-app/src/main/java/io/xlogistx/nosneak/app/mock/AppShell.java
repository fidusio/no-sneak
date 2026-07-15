package io.xlogistx.nosneak.app.mock;


import gui.AssistantPanel;
import io.xlogistx.nosneak.app.mock.utility.AppContext;
import io.xlogistx.nosneak.app.mock.utility.Navigator;
import io.xlogistx.nosneak.app.mock.utility.SessionAICredentialSource;

import javax.swing.*;
import java.awt.*;

public class AppShell extends JPanel {
    private final CardLayout cards = new CardLayout();
    private final JPanel content = new JPanel(cards);
    private final AppContext ctx;

    // import assistant panel from ai-assistant gui
    private final AssistantPanel assistantPanel;

    public AppShell(AppContext ctx) {
        setLayout(new BorderLayout());
        this.ctx = ctx;

        assistantPanel = new AssistantPanel(new SessionAICredentialSource(ctx.session()));

        content.add(new LoginPanel(ctx), Navigator.Screen.LOGIN.name());
        content.add(new PQCRegistryPanel(ctx), Navigator.Screen.MAIN.name());
        content.add(new SubjectPanel(ctx), Navigator.Screen.SUBJECT.name());
        content.add(new ScanPanel(ctx), Navigator.Screen.SCAN.name());
        content.add(new SubjectSecManagerPanel(ctx), Navigator.Screen.MANAGER.name());
        content.add(assistantPanel, Navigator.Screen.ASSISTANT.name());

        add(buildContent(), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        ctx.setNavigator(new Navigator(cards, content));
        ctx.session().onAuthChange(e -> {
            if ((boolean) e.getNewValue()) {
                ctx.nav().show(Navigator.Screen.SUBJECT);

                // load this subject's AI provider keys into the assistant
                assistantPanel.refresh();
            } else {
                ctx.nav().show(Navigator.Screen.LOGIN);

                // reset ai assistant panel
                assistantPanel.cleanup();
            }
        });

        ctx.nav().show(Navigator.Screen.LOGIN);
    }

    private JPanel buildContent() {

        cards.show(content, Navigator.Screen.LOGIN.name());
        return content;
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        JLabel session = new JLabel("session: none | subject: --");
        JLabel status = new JLabel("Ready");

        ctx.session().onAuthChange(e -> {
            if ((boolean) e.getNewValue()) {
                session.setText("session: mock-build | subject: " + ctx.session().getPrincipalID());
            } else {
                session.setText("session: none | subject: --");
            }
        });

        footer.add(session, BorderLayout.WEST);
        footer.add(status, BorderLayout.EAST);

        return footer;
    }
}