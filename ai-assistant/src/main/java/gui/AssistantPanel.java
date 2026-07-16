package gui;

import agent.AICredentialSource;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.PanelBuilder;
import org.zoxweb.shared.security.APIKey;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class AssistantPanel extends JPanel {

    private final CardStack cardStack = new CardStack();
    private final AICredentialSource credentials;

    // Repopulated by refresh() so the list tracks login/logout (credentials() is empty until login).
    private final JPanel providersList = new JPanel();

    public AssistantPanel(AICredentialSource credentials) {
        this.credentials = credentials;
        providersList.setLayout(new BoxLayout(providersList, BoxLayout.Y_AXIS));

        setLayout(new BorderLayout());

        cardStack.add(new JScrollPane(buildPromptPanel()), "chat");
        cardStack.add(new JScrollPane(buildJobQueuePanel()), "queue");
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

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), chatButton, historyButton, skillsButton, providersButton));

        refreshProviders();
    }

    public JPanel buildPromptPanel() {
        return new JPanel();
    }

    public JPanel buildJobQueuePanel() {
        return new JPanel();
    }

    public JPanel buildHistoryPanel() {
        return new JPanel();
    }

    public JPanel buildSkillsPanel() {
        return new JPanel();
    }

    public JPanel buildProvidersPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(providersList, BorderLayout.NORTH);   // hug the top
        return panel;
    }

    /** Rebuilds the provider list from the current credentials. Never renders the secret. */
    private void refreshProviders() {
        providersList.removeAll();

        List<APIKey<String>> creds = credentials.APIKeys();
        if (creds.isEmpty()) {
            providersList.add(new JLabel(
                    "No AI provider keys. Add one under Subject → Credentials and tick \"Use for AI assistant\"."));
        } else {
            for (APIKey<String> c : creds) {
                providersList.add(new JLabel(c.getName() + "  —  " + c.getProperties().getValue("provider") + "  @  " + c.getProperties().getValue("base_url")));
            }
        }

        providersList.revalidate();
        providersList.repaint();
    }

    public void refresh() {
        if (SwingUtilities.isEventDispatchThread()) refreshProviders();
        else SwingUtilities.invokeLater(this::refreshProviders);
    }

    public void cleanup() {
        refresh();   // logged out → credentials() is empty → clears the list
    }
}