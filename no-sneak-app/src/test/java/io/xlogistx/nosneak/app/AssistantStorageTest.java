package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIProviderConfig;
import io.xlogistx.nosneak.ai.model.AISkill;
import io.xlogistx.nosneak.app.ui.assistant.AssistantStorage;
import io.xlogistx.nosneak.app.ui.utility.Session;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.DomainSecurityManagerDefault;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.MockAPIDataStore;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.DomainSecurityManager;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Guards {@link AssistantStorage}'s persistence contract over the datastore:
 *
 * <ol>
 *   <li>The insert-vs-update branch keys on {@code getGUID()} — branching on the deprecated
 *       {@code referenceID} (always null on the store) made every save an insert and duplicated
 *       the row on each edit.</li>
 *   <li>{@code lastTimeUpdated} is stamped on the <em>update</em> branch only: the store's
 *       {@code MetaUtil.initTimeStamp} never advances it, and stamping on insert would land
 *       creation and update a millisecond apart on a fresh row.</li>
 *   <li>Signed-out reads return empty rather than leaking another subject's rows.</li>
 * </ol>
 */
public class AssistantStorageTest {

    private static final String PWD = "Password1!";

    private static Session freshLoggedInSession() {
        DomainSecurityManager dsm =
                new DomainSecurityManagerDefault().setDataStore(new MockAPIDataStore())
                        .addCredentialType(CIPassword.class);
        dsm.createSubjectID("kailen", HashUtil.toBCryptPassword(PWD));
        Session s = new Session(dsm);
        s.loginUsernamePassword("kailen", PWD.toCharArray());
        return s;
    }

    @Test
    public void chatInsertAssignsGuidAndOwner() {
        Session s = freshLoggedInSession();
        AssistantStorage storage = new AssistantStorage(s);

        AIChat chat = new AIChat("first chat");
        long beforeInsert = chat.getLastTimeUpdated();
        AIChat saved = storage.saveChat(chat);

        assertNotNull(saved.getGUID(), "the store must assign a GUID on insert");
        assertFalse(saved.getGUID().isEmpty());
        assertEquals(s.getSubjectGUID(), saved.getSubjectGUID(), "insert must stamp the owner");
        assertEquals(beforeInsert, saved.getLastTimeUpdated(),
                "the insert branch must NOT re-stamp lastTimeUpdated — only updates advance it");
    }

    @Test
    public void chatUpdateStampsLastTimeUpdated() {
        Session s = freshLoggedInSession();
        AssistantStorage storage = new AssistantStorage(s);
        AIChat saved = storage.saveChat(new AIChat("first chat"));

        long before = System.currentTimeMillis();
        storage.saveChat(saved);

        assertTrue(saved.getLastTimeUpdated() >= before,
                "a save of a GUID-bearing chat is an update and must stamp lastTimeUpdated");
    }

    @Test
    public void chatSaveIsUpsertByGuid() {
        Session s = freshLoggedInSession();
        AssistantStorage storage = new AssistantStorage(s);

        AIChat saved = storage.saveChat(new AIChat("original title"));
        saved.setTitle("renamed");
        storage.saveChat(saved);

        assertEquals(1, storage.getAllChats().size(),
                "editing a saved chat must update the row, not duplicate it");
        assertEquals("renamed", storage.getAllChats().getFirst().getTitle());
    }

    @Test
    public void skillInsertAndUpdateMirrorChatBehaviour() {
        Session s = freshLoggedInSession();
        AssistantStorage storage = new AssistantStorage(s);

        AISkill skill = new AISkill();
        skill.setName("summarize");
        skill.setContent("# instructions");
        long beforeInsert = skill.getLastTimeUpdated();
        AISkill saved = storage.saveSkill(skill);

        assertNotNull(saved.getGUID());
        assertEquals(s.getSubjectGUID(), saved.getSubjectGUID());
        assertEquals(beforeInsert, saved.getLastTimeUpdated());

        long before = System.currentTimeMillis();
        storage.saveSkill(saved);
        assertTrue(saved.getLastTimeUpdated() >= before);
        assertEquals(1, storage.getAllSkills().size());
    }

    @Test
    public void signedOutReadsReturnEmpty() {
        Session s = freshLoggedInSession();
        AssistantStorage storage = new AssistantStorage(s);
        storage.saveChat(new AIChat("mine"));

        s.logout();

        assertTrue(storage.getAllChats().isEmpty(), "signed out must read no chats");
        assertTrue(storage.getAllSkills().isEmpty(), "signed out must read no skills");
        assertTrue(storage.getAllProviderConfigs().isEmpty(), "signed out must read no providers");
    }

    @Test
    public void providerConfigRoundTripsEveryField() {
        Session s = freshLoggedInSession();
        AssistantStorage storage = new AssistantStorage(s);

        AIProviderConfig config = new AIProviderConfig("Claude prod", "key-guid-1", "anthropic");
        config.setBaseURL("https://gateway.internal/v1");
        config.setDefaultModel("claude-sonnet-4");
        AIProviderConfig saved = storage.saveProviderConfig(config);

        assertNotNull(saved.getGUID(), "the store must assign a GUID on insert");
        assertEquals(s.getSubjectGUID(), saved.getSubjectGUID(), "insert must stamp the owner");

        AIProviderConfig read = storage.getAllProviderConfigs().getFirst();
        assertEquals("Claude prod", read.getName(), "the editable label must round-trip");
        assertEquals("key-guid-1", read.getKeyGUID());
        assertEquals("anthropic", read.getProviderType());
        assertEquals("https://gateway.internal/v1", read.getBaseURL());
        assertEquals("claude-sonnet-4", read.getDefaultModel());
        assertTrue(read.isEnabled());
    }

    @Test
    public void oneKeyBacksSeveralProviderConfigs() {
        Session s = freshLoggedInSession();
        AssistantStorage storage = new AssistantStorage(s);

        storage.saveProviderConfig(new AIProviderConfig("direct", "shared-key", "anthropic"));
        AIProviderConfig viaGateway = new AIProviderConfig("via gateway", "shared-key", "anthropic");
        viaGateway.setBaseURL("https://gateway.internal/v1");
        storage.saveProviderConfig(viaGateway);

        assertEquals(2, storage.getAllProviderConfigs().size(),
                "two configs may borrow the same credential — they are distinct providers");
    }

    @Test
    public void providerConfigSaveIsUpsertByGuid() {
        Session s = freshLoggedInSession();
        AssistantStorage storage = new AssistantStorage(s);

        AIProviderConfig saved =
                storage.saveProviderConfig(new AIProviderConfig("old label", "key-guid-1", "openai"));
        saved.setName("new label");
        storage.saveProviderConfig(saved);

        assertEquals(1, storage.getAllProviderConfigs().size(),
                "relabelling must update the row, not duplicate it");
        assertEquals("new label", storage.getAllProviderConfigs().getFirst().getName());
    }

    @Test
    public void providerConfigDeleteRemovesTheRow() {
        Session s = freshLoggedInSession();
        AssistantStorage storage = new AssistantStorage(s);

        AIProviderConfig saved =
                storage.saveProviderConfig(new AIProviderConfig("temp", "key-guid-1", "grok"));
        storage.deleteProviderConfig(saved);

        assertTrue(storage.getAllProviderConfigs().isEmpty());
    }
}
