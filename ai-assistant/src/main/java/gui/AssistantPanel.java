package gui;

import agent.model.*;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.ListSection;
import io.xlogistx.gui.PanelBuilder;
import org.zoxweb.shared.security.APIKey;

import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.util.NVEntity;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import static gui.Util.chatBubble;

public class AssistantPanel extends JPanel {

    private final CardStack cardStack = new CardStack();
    private final AssistantContext context;

    // Repopulated by refresh() so the list tracks login/logout (credentials() is empty until login).
    private final JPanel providersList = new JPanel();

    private ListSection skillsList;
    private List<AISkill> skills = new ArrayList<>();

    private JPanel transcript;
    private JScrollPane transcriptScroll;
    private JTextArea composer;


    public AssistantPanel(AssistantContext context) {
        this.context = context;
        providersList.setLayout(new BoxLayout(providersList, BoxLayout.Y_AXIS));

        setLayout(new BorderLayout());

        cardStack.add(buildPromptPanel(), "chat");
        cardStack.add(new JScrollPane(buildJobQueuePanel()), "queue");
        cardStack.add(new JScrollPane(buildHistoryPanel()), "history");
        cardStack.add(new JScrollPane(buildSkillsPanel()), "skills");
        cardStack.add(new JScrollPane(buildProvidersPanel()), "providers");

        JToggleButton chatButton = new JToggleButton("Chat");
        chatButton.addActionListener(_ -> cardStack.show("chat"));

        JToggleButton jobQueueButton = new JToggleButton("Job Queue");
        jobQueueButton.addActionListener(_ -> cardStack.show("queue"));

        JToggleButton historyButton = new JToggleButton("History");
        historyButton.addActionListener(_ -> cardStack.show("history"));

        JToggleButton skillsButton = new JToggleButton("Skills");
        skillsButton.addActionListener(_ -> cardStack.show("skills"));

        JToggleButton providersButton = new JToggleButton("Providers");
        providersButton.addActionListener(_ -> cardStack.show("providers"));

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), chatButton, jobQueueButton, historyButton, skillsButton, providersButton));

        refreshProviders();

        context.onChange("currentChat", e -> {

        });
    }

    public JPanel buildPromptPanel() {
        transcript = new JPanel(new MigLayout("wrap 1, insets 14, gapy 10", "[grow]"));

        transcriptScroll = new JScrollPane(transcript,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        transcriptScroll.setBorder(BorderFactory.createEmptyBorder());
        transcriptScroll.getVerticalScrollBar().setUnitIncrement(16);

        composer = new JTextArea(1, 20);
        composer.setLineWrap(true);
        composer.setWrapStyleWord(true);
        composer.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        composer.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "chat-send");
        composer.getActionMap().put("chat-send", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                onSend();
            }
        });
        composer.getInputMap().put(
                KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.SHIFT_DOWN_MASK), "insert-break");

        JScrollPane composerScroll = new JScrollPane(composer,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        composerScroll.setPreferredSize(new Dimension(0, 44));

        JButton send = new JButton("Send");
        send.addActionListener(_ -> onSend());

        JPanel composerBar = new JPanel(new BorderLayout(8, 0));
        composerBar.setBorder(BorderFactory.createEmptyBorder(8, 14, 12, 14));
        composerBar.add(composerScroll, BorderLayout.CENTER);
        composerBar.add(send, BorderLayout.EAST);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(transcriptScroll, BorderLayout.CENTER);
        panel.add(composerBar, BorderLayout.SOUTH);
        return panel;
    }

    private void refreshPrompt() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshPrompt);
            return;
        }
        transcript.removeAll();

        AIChat chat = context.currentChat();
        if (chat != null) {
            for (NVEntity e : chat.getMessages().values()) {
                AIMessage m = (AIMessage) e;
                AIRequest req = m.getAIRequest();
                if (req != null && req.getContent() != null) addMessage(req.getContent(), true);
                AIResponse res = m.getAIResponse();
                if (res != null && res.getContent() != null) addMessage(res.getContent(), false);
            }
        }

        transcript.revalidate();
        transcript.repaint();
    }

    private void onSend() {
        String text = composer.getText().trim();
        if (text.isEmpty()) return;
        addMessage(text, true);
        composer.setText("");
        composer.requestFocusInWindow();
        context.getCurrentChat().startTurn(composer.getText(), 100);
    }

    private void addMessage(String text, boolean user) {
        JComponent bubble = chatBubble(text, user);
        transcript.add(bubble, "wmax 78%, alignx " + (user ? "trailing" : "leading"));
        transcript.revalidate();
        transcript.repaint();

        SwingUtilities.invokeLater(() -> {
            JScrollBar v = transcriptScroll.getVerticalScrollBar();
            v.setValue(v.getMaximum());
        });
    }

    private void onResponse(String response) {
        String text = response;
        if (text.isEmpty()) return;
        addMessage(text, false);
    }

    public JPanel buildJobQueuePanel() {
        return new JPanel();
    }

    public JPanel buildHistoryPanel() {
        JPanel out = new JPanel();
        //ListSection list = new ListSection();
        return out;
    }

    public JPanel buildSkillsPanel() {
        skillsList = new ListSection("Skills", "+ Add skill", null, this::skillEntries);
        return skillsList;
    }


    private List<ListSection.Entry> skillEntries() {
        List<ListSection.Entry> out = new ArrayList<>();

        for (AISkill skill : skills) {
            out.add(new ListSection.Entry(skill.getName(), null, null));
        }

        return out;
    }

    private void onAddSkill() {

    }

    public JPanel buildProvidersPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(providersList, BorderLayout.NORTH);   // hug the top
        return panel;
    }

    /**
     * Rebuilds the provider list from the current credentials. Never renders the secret.
     */
    private void refreshProviders() {
        providersList.removeAll();

        List<APIKey<String>> creds = context.getCredentials().APIKeys();
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