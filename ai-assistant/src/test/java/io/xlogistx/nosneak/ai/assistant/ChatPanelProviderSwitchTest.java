package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.api.ai.AIAPI;
import io.xlogistx.nosneak.ai.AIException;
import io.xlogistx.nosneak.ai.AIModelCatalog;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.panels.ChatPanel;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIRequest;
import io.xlogistx.nosneak.ai.model.AIResponse;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.io.UByteArrayInputStream;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.task.ConsumerCallback;
import org.zoxweb.shared.util.NVGenericMap;

import javax.swing.*;
import java.awt.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Switching the assistant inside a chat (2026-10-28, the maintainer's "the model filter should
 * be updated properly, now it hangs on the old one"): text typed into the model combo to narrow
 * the old provider's list must not survive the switch, and the list must be the new provider's.
 * Since the same day the model combo is a gui-audio {@code FilterComboBox}: the filter is what
 * is typed in its editor. Drives a real {@link ChatPanel} over two fake providers with fixed
 * catalogs.
 */
public class ChatPanelProviderSwitchTest {

    /** A provider that only knows its id, name and model list. */
    private static final class FakeProvider implements AIProvider {
        private final String id;
        private final String[] models;

        FakeProvider(String id, String... models) {
            this.id = id;
            this.models = models;
        }

        public String getID() { return id; }
        public String getName() { return id; }
        public String getDescription() { return null; }

        public AIModelCatalog getModelCatalog() {
            return new AIModelCatalog() {
                public String[] models() { return models; }
                public String[] refresh() { return models; }
                public Instant lastSynced() { return Instant.EPOCH; }
            };
        }

        public void setAPIKey(APIKey<String> key) { }
        public APIKey<String> getAPIKey() { return null; }
        public void setHTTPAPICaller(AIAPI caller) { }
        public AIAPI getHTTPAPICaller() { return null; }
        public AIResponse send(AIRequest req, String skill) throws AIException { throw new UnsupportedOperationException(); }
        public void asyncSend(AIRequest req, String skill, ConsumerCallback<NVGenericMap> cb) { throw new UnsupportedOperationException(); }
        public void asyncImageSend(AIRequest req, String skill, ConsumerCallback<NVGenericMap> cb, UByteArrayInputStream... images) { throw new UnsupportedOperationException(); }
    }

    private static <T extends Component> List<T> all(Component root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        if (root instanceof Container c) for (Component k : c.getComponents()) all(k, type, out);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static JComboBox<String> comboHolding(Component root, String item) {
        for (JComboBox<?> box : all(root, JComboBox.class, new ArrayList<>()))
            for (int i = 0; i < box.getItemCount(); i++)
                if (item.equals(box.getItemAt(i))) return (JComboBox<String>) box;
        return null;
    }

    private static List<String> items(JComboBox<String> box) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < box.getItemCount(); i++) out.add(box.getItemAt(i));
        return out;
    }

    @Test
    public void switchingProviderDropsTheFilterAndListsTheNewModels() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AssistantContextTest.MemoryRepository repo = new AssistantContextTest.MemoryRepository();
            AssistantContext ctx = new AssistantContext(null, repo);
            ctx.getProviders().put("claude", new FakeProvider("claude", "claude-sonnet", "claude-opus"));
            ctx.getProviders().put("gpt", new FakeProvider("gpt", "gpt-5", "gpt-5-mini"));
            ChatPanel panel = new ChatPanel(ctx);
            AIChat chat = repo.saveChat(new AIChat("posture"));
            chat.setProvider("claude");
            chat.setModel("claude-sonnet");
            ctx.setCurrentChat(chat);

            JComboBox<String> providers = comboHolding(panel, "gpt");
            JComboBox<String> models = comboHolding(panel, "claude-sonnet");
            assertNotNull(providers, "the conversation's provider combo lists both");
            assertNotNull(models, "the model combo starts with the bound provider's models");
            assertEquals("claude-sonnet", models.getSelectedItem());

            JTextField editor = (JTextField) models.getEditor().getEditorComponent();
            editor.setText("sonnet");
            flush.run();
            assertEquals(List.of("claude-sonnet"), items(models), "typing narrows the old provider's list");

            providers.setSelectedItem("gpt");

            assertEquals("gpt", chat.getProvider(), "the chat is rebound");
            assertEquals(List.of("gpt-5", "gpt-5-mini"), items(models), "the list is the new provider's, unfiltered");
            assertEquals("gpt-5", chat.getModel(), "no default model on the fake, so the first one");
            assertEquals("gpt-5", editor.getText(), "and the combo shows it, the typed filter is gone");
        });
    }

    /** Runs the filter's deferred EDT turn from inside an EDT block. */
    private static final Runnable flush = () -> {
        try {
            java.awt.EventQueue eq = java.awt.Toolkit.getDefaultToolkit().getSystemEventQueue();
            java.awt.AWTEvent e;
            while ((e = eq.peekEvent(java.awt.event.InvocationEvent.INVOCATION_DEFAULT)) != null) {
                eq.getNextEvent();
                ((java.awt.event.InvocationEvent) e).dispatch();
            }
        } catch (InterruptedException ignored) {
        }
    };

    @Test
    public void switchingWithABlankFilterStillRefills() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AssistantContextTest.MemoryRepository repo = new AssistantContextTest.MemoryRepository();
            AssistantContext ctx = new AssistantContext(null, repo);
            ctx.getProviders().put("claude", new FakeProvider("claude", "claude-sonnet"));
            ctx.getProviders().put("gpt", new FakeProvider("gpt", "gpt-5"));
            ChatPanel panel = new ChatPanel(ctx);
            AIChat chat = repo.saveChat(new AIChat("posture"));
            chat.setProvider("claude");
            ctx.setCurrentChat(chat);

            JComboBox<String> models = comboHolding(panel, "claude-sonnet");
            comboHolding(panel, "gpt").setSelectedItem("gpt");
            assertEquals(List.of("gpt-5"), items(models));
            assertEquals("gpt-5", chat.getModel());
        });
    }
}
