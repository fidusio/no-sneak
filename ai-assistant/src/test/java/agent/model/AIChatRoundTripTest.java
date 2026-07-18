package agent.model;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for the {@link AIChat} / {@link AIMessage} DAOs. Exercises construction,
 * message appending, and JSON serialize &rarr; deserialize (the file-store path a
 * {@code FileAIChatStore} will use) with no store implementation written yet.
 *
 * <p>Guards the three runtime bugs found during design — all of which compiled cleanly and
 * only failed when the object was constructed or (de)serialized:</p>
 * <ol>
 *   <li>{@code AIChat} could not be constructed (MESSAGES declared with scalar
 *       {@code createNVConfig} instead of {@code createNVConfigEntity(..., ArrayType.LIST)}).</li>
 *   <li>{@code AIMessage} role could not round-trip (the {@code Role} enum was stored into a
 *       {@code String}-typed field).</li>
 *   <li>GSON could not deserialize a chat back (the no-arg constructors were {@code protected}).</li>
 * </ol>
 */
public class AIChatRoundTripTest {

    private static AIChat sampleChat() {
        AIChat c = new AIChat("planning chat");
        c.setModel("claude-opus-4-8");
        c.setSystemPrompt("You are helpful.");
        c.addUser("what is 2+2?");
        c.addAssistant("4");
        return c;
    }

    /** Construction + append (guards bugs 1 and 2). */
    @Test
    public void constructsAndAppendsMessages() {
        AIChat c = sampleChat();

        assertNotNull(c.getTopicID(), "topicID should be generated");
        assertEquals("claude-opus-4-8", c.getModel());
        assertEquals(2, c.getMessages().size());

        AIMessage first = (AIMessage) c.getMessages().values()[0];
        assertEquals(AIMessage.Role.USER, first.getRole());
        assertEquals("what is 2+2?", first.getContent());
        assertTrue(first.getCreationTime() > 0, "message timestamp should be set");

        AIMessage second = (AIMessage) c.getMessages().values()[1];
        assertEquals(AIMessage.Role.ASSISTANT, second.getRole());
        assertEquals("4", second.getContent());
    }

    /** JSON serialize then deserialize — the file-store path (guards bug 3 + serialization). */
    @Test
    public void jsonRoundTripPreservesChat() {
        AIChat original = sampleChat();

        String json = GSONUtil.toJSONDefault(original, false);
        AIChat restored = GSONUtil.fromJSONDefault(json, AIChat.class);

        assertEquals(original.getTitle(), restored.getTitle());
        assertEquals(original.getTopicID(), restored.getTopicID());
        assertEquals(original.getModel(), restored.getModel());
        assertEquals(original.getSystemPrompt(), restored.getSystemPrompt());
        assertEquals(original.getCreationTime(), restored.getCreationTime());

        assertEquals(2, restored.getMessages().size());

        AIMessage user = (AIMessage) restored.getMessages().values()[0];
        assertEquals(AIMessage.Role.USER, user.getRole());
        assertEquals("what is 2+2?", user.getContent());

        AIMessage assistant = (AIMessage) restored.getMessages().values()[1];
        assertEquals(AIMessage.Role.ASSISTANT, assistant.getRole());
        assertEquals("4", assistant.getContent());
    }

    /**
     * {@link AIModel} is cached by {@code AIModelCatalog}; if that cache is persisted it goes
     * through the same JSON path. Guards the {@code protected}-constructor deserialize bug here too.
     */
    @Test
    public void aiModelJsonRoundTrip() {
        AIModel original = new AIModel("claude", "claude-opus-4-8");

        String json = GSONUtil.toJSONDefault(original, false);
        AIModel restored = GSONUtil.fromJSONDefault(json, AIModel.class);

        assertEquals("claude", restored.getProvider());
        assertEquals("claude-opus-4-8", restored.getModelID());
    }

    /** {@code toRequest} snapshots the chat's config + full history into a stateless request. */
    @Test
    public void toRequestSnapshotsHistory() {
        AIChat c = sampleChat();

        AIRequest req = c.toRequest(4096, null);

        assertEquals("claude-opus-4-8", req.getModel());
        assertEquals("You are helpful.", req.getSystemPrompt());
        assertEquals(c.getTopicID(), req.getTopicID());
        assertEquals(4096, req.getMaxTokens());
        assertNotNull(req.getCorrelationID(), "correlationID should be auto-generated");

        assertEquals(2, req.getMessages().size());
        assertEquals(AIMessage.Role.USER, req.getMessages().get(0).getRole());
        assertEquals("what is 2+2?", req.getMessages().get(0).getContent());
        assertEquals(AIMessage.Role.ASSISTANT, req.getMessages().get(1).getRole());
    }
}