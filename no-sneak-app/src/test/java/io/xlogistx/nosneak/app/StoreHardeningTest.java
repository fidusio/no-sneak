package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIMessage;
import io.xlogistx.nosneak.ai.model.AIRequest;
import io.xlogistx.nosneak.ai.model.AIResponse;
import io.xlogistx.nosneak.app.ui.assistant.AssistantStorage;
import io.xlogistx.nosneak.app.ui.utility.Session;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.security.AccessSecurityException;

import java.io.File;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The two hardening rules the in-memory {@code MockAPIDataStore} cannot exercise, run on a real
 * installation set up by {@code H2PSetup} the way {@link DataStoreSetupFlowTest} does:
 * <ol>
 *   <li>{@link AssistantStorage#deleteChat} cascades — the chat's {@code ai_message} rows and
 *       their {@code ai_request} / {@code ai_response} rows are gone with it (until 2026-10-27
 *       the delete passed {@code withReference=false} and they stayed forever);</li>
 *   <li>{@link Session#addIdentifier} refuses an identifier already in use — the rule lives in
 *       the manager and the store's unique index, which the mock has no notion of.</li>
 * </ol>
 * Each test gets a fresh directory under {@code target/} rather than a {@code @TempDir}: the H2
 * URL carries {@code DB_CLOSE_DELAY=-1}, so the file stays locked after the store closes.
 */
public class StoreHardeningTest {

    private static final String OPERATOR = "operator.local";
    private static final String OPERATOR_PWD = "Operat0r-pass!";

    private static ShiroDSDomainSecurityManager freshStore() throws Exception {
        File dir = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(dir.mkdirs() || dir.isDirectory(), "cannot create " + dir);
        NoSneakStore.FirstRun firstRun = new NoSneakStore.FirstRun(OPERATOR, OPERATOR_PWD.toCharArray(), "", null, null);
        return NoSneakStore.create(dir.getPath(), "V4ult-pass!".toCharArray(), firstRun);
    }

    @Test
    public void deletingAChatRemovesItsMessageRequestAndResponseRows() throws Exception {
        ShiroDSDomainSecurityManager dsm = freshStore();
        try {
            Session session = new Session(dsm);
            session.loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
            AssistantStorage storage = new AssistantStorage(session);
            APIDataStore<?, ?> ds = session.getDataStore();

            AIChat chat = new AIChat();
            chat.setName("cascade");
            chat.setModel("test-model");
            AIMessage turn = chat.startTurn("hello", 100);
            AIResponse reply = new AIResponse();
            reply.setContent("hi");
            turn.setAIResponse(reply);
            AIChat saved = storage.saveChat(chat);
            assertNotNull(saved.getGUID(), "the store assigns the GUID");
            assertEquals(1, ds.search(AIMessage.NVC_AI_MESSAGE, null).size(), "the turn is a row of its own");
            assertEquals(1, ds.search(AIRequest.NVC_AI_REQUEST, null).size());
            assertEquals(1, ds.search(AIResponse.NVC_AI_RESPONSE, null).size());

            storage.deleteChat(saved);

            assertTrue(storage.getAllChats().isEmpty(), "the chat is gone");
            assertTrue(ds.search(AIMessage.NVC_AI_MESSAGE, null).isEmpty(), "its messages go with it");
            assertTrue(ds.search(AIRequest.NVC_AI_REQUEST, null).isEmpty(), "and their requests");
            assertTrue(ds.search(AIResponse.NVC_AI_RESPONSE, null).isEmpty(), "and their responses");
            session.logout();
        } finally {
            dsm.getDataStore().close();
        }
    }

    @Test
    public void addIdentifierRefusesOneAlreadyInUse() throws Exception {
        ShiroDSDomainSecurityManager dsm = freshStore();
        try {
            Session session = new Session(dsm);
            session.registerUsernamePassword("alice-tester", "Password9!".toCharArray());
            session.loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
            int before = session.getAllPrincipalIDForLoggedInUser().size();

            // another subject's identifier, and the operator's own
            String other = assertThrows(AccessSecurityException.class,
                    () -> session.addIdentifier("alice-tester")).getMessage();
            assertTrue(other.startsWith("Principal ID already exists"), other);
            String own = assertThrows(AccessSecurityException.class,
                    () -> session.addIdentifier(OPERATOR)).getMessage();
            assertTrue(own.startsWith("Principal ID already exists"), own);
            assertEquals(before, session.getAllPrincipalIDForLoggedInUser().size(), "nothing was added");

            assertDoesNotThrow(() -> session.addIdentifier("operator@example.test"), "a fresh one is fine");
            assertEquals(before + 1, session.getAllPrincipalIDForLoggedInUser().size());
            session.logout();
        } finally {
            dsm.getDataStore().close();
        }
    }
}
