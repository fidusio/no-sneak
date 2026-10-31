package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.api.ai.AIAPIBuilder;
import io.xlogistx.nosneak.ai.assistant.panels.ChatPanel;
import io.xlogistx.nosneak.ai.model.AIProviderConfig;
import okhttp3.OkHttpClient;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.HTTPAPIEndPoint;
import org.zoxweb.shared.security.SubjectAPIKey;

import java.io.IOException;
import java.net.SocketTimeoutException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The assistant's reply timeout (2026-10-31). zoxweb's default http client gives up on a read
 * after 40 s, right for a responsive endpoint, and ignores the message config's timeout on the
 * ordinary path; so the limit the subject stretches for a congested endpoint is one shared
 * {@link OkHttpClient} on {@link AssistantContext}, rebuilt when the setting changes and pushed
 * to every registered {@link AIAPIProvider}'s endpoints.
 */
public class CallTimeoutTest {

    private static AIAPIProvider provider(String guid) {
        AIProviderConfig config = new AIProviderConfig();
        config.setProviderType("openai");
        config.setGUID(guid);
        SubjectAPIKey key = new SubjectAPIKey();
        key.setAPIKey("not-a-real-key");
        return new AIAPIProvider(config, key, AIAPIBuilder.AIAPIType.OPEN_AI);
    }

    private static void assertEveryEndpoint(AIAPIProvider p, Integer readMillis) {
        HTTPAPIEndPoint<?, ?>[] endpoints = p.getHTTPAPICaller().getEndPoints();
        assertTrue(endpoints.length > 0);
        for (HTTPAPIEndPoint<?, ?> ep : endpoints) {
            if (readMillis == null) assertNull(ep.getOkHttpClient(), ep.getConfig().getURI());
            else assertEquals(readMillis, ep.getOkHttpClient().readTimeoutMillis(), ep.getConfig().getURI());
        }
    }

    @Test
    public void theContextStartsOnTheDefaultWithAClientBuiltForIt() {
        AssistantContext ctx = new AssistantContext(null, null);
        assertEquals(AssistantContext.DEFAULT_CALL_TIMEOUT_SECONDS, ctx.getCallTimeoutSeconds());
        assertEquals(AssistantContext.DEFAULT_CALL_TIMEOUT_SECONDS * 1000, ctx.getHttpClient().readTimeoutMillis());
    }

    @Test
    public void theClientCarriesTheTimeoutOnEveryLeg() {
        AssistantContext ctx = new AssistantContext(null, null);
        ctx.setCallTimeoutSeconds(90);
        OkHttpClient c = ctx.getHttpClient();
        assertNotNull(c);
        assertEquals(90_000, c.readTimeoutMillis());
        assertEquals(90_000, c.connectTimeoutMillis());
        assertEquals(90_000, c.writeTimeoutMillis());
        assertTrue(c.followRedirects());
    }

    @Test
    public void zeroAndBelowMeanTheLibraryDefault() {
        AssistantContext ctx = new AssistantContext(null, null);
        ctx.setCallTimeoutSeconds(0);
        assertNull(ctx.getHttpClient());
        ctx.setCallTimeoutSeconds(-5);
        assertEquals(0, ctx.getCallTimeoutSeconds());
        assertNull(ctx.getHttpClient());
    }

    @Test
    public void aChangePushesOneNewClientToEveryRegisteredProvider() {
        AssistantContext ctx = new AssistantContext(null, null);
        AIAPIProvider p = provider("p1");
        ctx.getProviders().put(p.getID(), p);

        ctx.setCallTimeoutSeconds(75);
        assertEveryEndpoint(p, 75_000);
        OkHttpClient first = ctx.getHttpClient();

        ctx.setCallTimeoutSeconds(300);
        assertEveryEndpoint(p, 300_000);
        assertNotSame(first, ctx.getHttpClient(), "a change builds a new client");
        assertSame(ctx.getHttpClient(), p.getHTTPAPICaller().getEndPoints()[0].getOkHttpClient(), "the endpoints hold the shared one");

        ctx.setCallTimeoutSeconds(0);
        assertEveryEndpoint(p, null);
    }

    @Test
    public void aProviderBuiltLaterGetsTheCurrentClientWhenApplied() {
        AssistantContext ctx = new AssistantContext(null, null);
        ctx.setCallTimeoutSeconds(45);
        AIAPIProvider p = provider("p2");
        ctx.applyHttpClient(p);
        assertEveryEndpoint(p, 45_000);
        assertSame(ctx.getHttpClient(), p.getHTTPAPICaller().getEndPoints()[0].getOkHttpClient());
    }

    @Test
    public void aTimedOutSendNamesTheSetting() {
        String hint = ChatPanel.timeoutHint(new IOException("wrapped", new SocketTimeoutException("timeout")), 120);
        assertTrue(hint.contains("within 120 s"), hint);
        assertTrue(hint.contains("Settings > Assistant"), hint);
        assertTrue(ChatPanel.timeoutHint(new RuntimeException("Read Timeout after 40 s"), 40).contains("within 40 s"));
        assertEquals("", ChatPanel.timeoutHint(new IOException("401 unauthorized"), 120));
        assertEquals("", ChatPanel.timeoutHint(null, 120));
    }
}
