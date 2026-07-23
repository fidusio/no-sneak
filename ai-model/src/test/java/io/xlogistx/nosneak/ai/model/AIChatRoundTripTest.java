package io.xlogistx.nosneak.ai.model;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for the {@link AIChat} / {@link AIMessage} / {@link AIRequest} /
 * {@link AIResponse} DAOs.
 *
 * <p>The model is a pair-based conversation: an {@link AIChat} holds an ordered list of
 * {@link AIMessage}s, and each {@code AIMessage} is one exchange — an {@link AIRequest}
 * (what was sent) plus an {@link AIResponse} (what came back). Roles are implicit in the
 * pair, not stored.</p>
 *
 * <p>These guard the invariants that only fail at construction or (de)serialization time:</p>
 * <ol>
 *   <li>{@code AIMessage} embeds {@code AIRequest}/{@code AIResponse} with
 *       {@code createNVConfigEntity} — using scalar {@code createNVConfig} compiles but drops
 *       the nested entity on JSON round-trip.</li>
 *   <li>{@code providerSessionID} is a stateful-provider handle: null for a fresh/stateless
 *       chat, and replayed onto the request only when present.</li>
 *   <li>GSON can reconstruct the whole tree (public no-arg constructors).</li>
 * </ol>
 */
public class AIChatRoundTripTest {

    private static final String MODEL = "claude-opus-4-8";

    /** A chat with one completed exchange (user asked, assistant answered). */
    private static AIChat sampleChat() {
        AIChat c = new AIChat("planning chat");
        c.setModel(MODEL);
        c.setSystemPrompt("You are helpful.");

        AIMessage turn = c.startTurn("what is 2+2?", 4096);
        AIResponse resp = new AIResponse();
        resp.setModel(MODEL);
        resp.setContent("4");
        resp.setTokens(3);
        resp.setLatency(120L);
        turn.setAIResponse(resp);

        return c;
    }

    /** Construction: title, config, and a stateless chat has no session handle yet. */
    @Test
    public void constructsChat() {
        AIChat c = new AIChat("planning chat");
        c.setModel(MODEL);

        assertEquals("planning chat", c.getTitle());
        assertEquals(MODEL, c.getModel());
        assertNull(c.getProviderSessionID(),
                "a fresh/stateless chat must not have a provider session id");
        assertTrue(c.getCreationTime() > 0, "creation timestamp should be set");
        assertEquals(0, c.getMessages().size());
    }

    /** startTurn wraps the user input in a request-only message and appends it to the chat. */
    @Test
    public void startTurnAppendsRequestOnlyMessage() {
        AIChat c = new AIChat("t");
        c.setModel(MODEL);

        AIMessage turn = c.startTurn("hello", 256);

        assertEquals(1, c.getMessages().size());
        assertSame(turn, c.getMessages().values()[0]);
        assertNotNull(turn.getAIRequest(), "request half must be populated");
        assertNull(turn.getAIResponse(), "response half is null until the provider replies");
        assertEquals("hello", turn.getAIRequest().getContent());
        assertEquals(256, turn.getAIRequest().getMaxTokens());
        assertEquals(MODEL, turn.getAIRequest().getModel());
    }

    /** Completing a turn attaches the response to the same message (the pair closes). */
    @Test
    public void completingTurnAttachesResponse() {
        AIChat c = sampleChat();

        AIMessage turn = (AIMessage) c.getMessages().values()[0];
        assertNotNull(turn.getAIResponse());
        assertEquals("what is 2+2?", turn.getAIRequest().getContent());
        assertEquals("4", turn.getAIResponse().getContent());
    }

    /** toRequest snapshots the chat's model + input into a single-turn request. */
    @Test
    public void toRequestBuildsSingleTurn() {
        AIChat c = new AIChat("t");
        c.setModel(MODEL);

        AIRequest req = c.toRequest("ping", 1024);

        assertEquals(MODEL, req.getModel());
        assertEquals("ping", req.getContent());
        assertEquals(1024, req.getMaxTokens());
        assertNull(req.getProviderSessionID(), "no session id to replay for a stateless chat");
    }

    /** When a stateful provider has issued a session id, toRequest replays it. */
    @Test
    public void toRequestReplaysProviderSessionID() {
        AIChat c = new AIChat("t");
        c.setModel(MODEL);
        c.setProviderSessionID("sess-123");   // as if lifted from a prior response

        AIRequest req = c.toRequest("again", 512);

        assertEquals("sess-123", req.getProviderSessionID());
    }

    /**
     * The key serialization guard: a chat with a completed exchange must survive JSON
     * round-trip with both halves of the {@link AIMessage} intact. This fails if
     * AI_REQUEST / AI_RESPONSE are declared with scalar {@code createNVConfig}.
     */
    @Test
    public void jsonRoundTripPreservesChatAndPair() {
        AIChat original = sampleChat();

        String json = GSONUtil.toJSONDefault(original, false);
        AIChat restored = GSONUtil.fromJSONDefault(json, AIChat.class);

        assertEquals(original.getTitle(), restored.getTitle());
        assertEquals(original.getModel(), restored.getModel());
        assertEquals(original.getSystemPrompt(), restored.getSystemPrompt());
        assertEquals(original.getCreationTime(), restored.getCreationTime());
        assertEquals(1, restored.getMessages().size());

        AIMessage turn = (AIMessage) restored.getMessages().values()[0];
        assertNotNull(turn.getAIRequest(), "request half lost in serialization");
        assertNotNull(turn.getAIResponse(), "response half lost in serialization");
        assertEquals("what is 2+2?", turn.getAIRequest().getContent());
        assertEquals("4", turn.getAIResponse().getContent());
        assertEquals(3, turn.getAIResponse().getTokens());
        assertEquals(120L, turn.getAIResponse().getLatency());
    }

    /** AIRequest/AIResponse each round-trip standalone (they persist independently too). */
    @Test
    public void requestAndResponseJsonRoundTrip() {
        AIRequest req = new AIRequest();
        req.setModel(MODEL);
        req.setContent("hi");
        req.setSkillsPrompt("be terse");
        req.setCorrelationID("corr-1");
        req.setProviderSessionID("sess-9");
        req.setMaxTokens(42);

        AIRequest rReq = GSONUtil.fromJSONDefault(GSONUtil.toJSONDefault(req, false), AIRequest.class);
        assertEquals(MODEL, rReq.getModel());
        assertEquals("hi", rReq.getContent());
        assertEquals("be terse", rReq.getSkillsPrompt());
        assertEquals("corr-1", rReq.getCorrelationID());
        assertEquals("sess-9", rReq.getProviderSessionID());
        assertEquals(42, rReq.getMaxTokens());

        AIResponse resp = new AIResponse();
        resp.setModel(MODEL);
        resp.setContent("hello");
        resp.setCorrelationID("corr-1");
        resp.setProviderSessionID("sess-9");
        resp.setTokens(7);
        resp.setLatency(88L);

        AIResponse rResp = GSONUtil.fromJSONDefault(GSONUtil.toJSONDefault(resp, false), AIResponse.class);
        assertEquals("hello", rResp.getContent());
        assertEquals("corr-1", rResp.getCorrelationID());
        assertEquals("sess-9", rResp.getProviderSessionID());
        assertEquals(7, rResp.getTokens());
        assertEquals(88L, rResp.getLatency());
    }

    /** {@link AIModel} is cached by the catalog; if persisted it goes through the same JSON path. */
    @Test
    public void aiModelJsonRoundTrip() {
        AIModel original = new AIModel("claude", MODEL);

        AIModel restored = GSONUtil.fromJSONDefault(GSONUtil.toJSONDefault(original, false), AIModel.class);

        assertEquals("claude", restored.getProvider());
        assertEquals(MODEL, restored.getModelID());
    }
}
