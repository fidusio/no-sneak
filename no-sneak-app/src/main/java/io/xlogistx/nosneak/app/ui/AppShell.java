package io.xlogistx.nosneak.app.ui;


import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.AssistantPanel;
import io.xlogistx.nosneak.app.ui.assistant.AssistantStorage;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
import io.xlogistx.nosneak.app.ui.assistant.SessionAICredentialSource;

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

        assistantPanel = new AssistantPanel(new AssistantContext(new SessionAICredentialSource(ctx.session()), new AssistantStorage(ctx.session().getDomainSecurityManager().getDataStore())));

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
                assistantPanel.reloadProviders();
            } else {
                ctx.nav().show(Navigator.Screen.LOGIN);
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