package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.AIRepository;
import io.xlogistx.nosneak.ai.model.AICapture;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIProviderConfig;
import io.xlogistx.nosneak.ai.model.AISkill;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Guards {@link AssistantContext}'s canonical-cache and event contract. The repository hands
 * out a fresh instance per read (as the H2P store does), so the context must dedupe by GUID:
 * the same chat/skill is one object across list refreshes, delete matches the current chat by
 * instance <em>or</em> GUID, and reset clears both caches. {@code referenceID} is always null
 * on persisted entities — GUID is the only usable key.
 */
public class AssistantContextTest {

    /** In-memory {@link AIRepository} that returns a fresh copy per read, like a real store. */
    private static final class MemoryRepository implements AIRepository {

        private final Map<String, AIChat> chats = new LinkedHashMap<>();
        private final Map<String, AISkill> skills = new LinkedHashMap<>();
        private final Map<String, AIProviderConfig> configs = new LinkedHashMap<>();
        private final Map<String, AICapture> captures = new LinkedHashMap<>();
        private int seq;

        @Override
        public AICapture saveCapture(AICapture capture) {
            if (capture.getGUID() == null || capture.getGUID().isEmpty()) capture.setGUID("capture-" + ++seq);
            captures.put(capture.getGUID(), capture);
            return capture;
        }

        @Override
        public void deleteCapture(AICapture capture) {
            if (capture.getGUID() != null) captures.remove(capture.getGUID());
        }

        @Override
        public AICapture getCapture(String guid) {
            return captures.get(guid);
        }

        @Override
        public List<AICapture> getAllCaptures() {
            return new ArrayList<>(captures.values());
        }

        @Override
        public AIProviderConfig saveProviderConfig(AIProviderConfig config) {
            if (config.getGUID() == null || config.getGUID().isEmpty()) config.setGUID("provider-" + ++seq);
            configs.put(config.getGUID(), config);
            return config;
        }

        @Override
        public void deleteProviderConfig(AIProviderConfig config) {
            if (config.getGUID() != null) configs.remove(config.getGUID());
        }

        @Override
        public AIProviderConfig getProviderConfig(String id) {
            return configs.get(id);
        }

        @Override
        public List<AIProviderConfig> getAllProviderConfigs() {
            List<AIProviderConfig> out = new ArrayList<>();
            for (AIProviderConfig c : configs.values()) {
                AIProviderConfig copy =
                        new AIProviderConfig(c.getName(), c.getKeyGUID(), c.getProviderType());
                copy.setGUID(c.getGUID());
                copy.setBaseURL(c.getBaseURL());
                copy.setDefaultModel(c.getDefaultModel());
                copy.setEnabled(c.isEnabled());
                out.add(copy);
            }
            return out;
        }

        @Override
        public AIChat saveChat(AIChat chat) {
            if (chat.getGUID() == null || chat.getGUID().isEmpty()) chat.setGUID("chat-" + ++seq);
            chats.put(chat.getGUID(), chat);
            return chat;
        }

        @Override
        public void deleteChat(AIChat chat) {
            if (chat.getGUID() != null) chats.remove(chat.getGUID());
        }

        @Override
        public AIChat getChat(String id) {
            return chats.get(id);
        }

        @Override
        public List<AIChat> getAllChats() {
            List<AIChat> out = new ArrayList<>();
            for (AIChat c : chats.values()) {
                AIChat copy = new AIChat(c.getTitle());
                copy.setGUID(c.getGUID());
                out.add(copy);
            }
            return out;
        }

        @Override
        public AISkill saveSkill(AISkill skill) {
            if (skill.getGUID() == null || skill.getGUID().isEmpty()) skill.setGUID("skill-" + ++seq);
            skills.put(skill.getGUID(), skill);
            return skill;
        }

        @Override
        public void deleteSkill(AISkill skill) {
            if (skill.getGUID() != null) skills.remove(skill.getGUID());
        }

        @Override
        public AISkill getSkill(String id) {
            return skills.get(id);
        }

        @Override
        public List<AISkill> getAllSkills() {
            List<AISkill> out = new ArrayList<>();
            for (AISkill s : skills.values()) {
                AISkill copy = new AISkill();
                copy.setName(s.getName());
                copy.setGUID(s.getGUID());
                out.add(copy);
            }
            return out;
        }
    }

    private static AssistantContext contextWithChat(MemoryRepository repo, String title) {
        repo.saveChat(new AIChat(title));
        return new AssistantContext(null, repo);
    }

    @Test
    public void repeatedListsShareCanonicalInstance() {
        MemoryRepository repo = new MemoryRepository();
        AssistantContext ctx = contextWithChat(repo, "planning");

        AIChat first = ctx.getAllChats().getFirst();
        AIChat second = ctx.getAllChats().getFirst();

        assertNotSame(repo.getAllChats().getFirst(), first, "the repository hands out fresh copies");
        assertSame(first, second, "the context must dedupe reads to one canonical instance per GUID");
    }

    @Test
    public void setCurrentChatCanonicalizesByGuid() {
        MemoryRepository repo = new MemoryRepository();
        AssistantContext ctx = contextWithChat(repo, "planning");
        AIChat canonical = ctx.getAllChats().getFirst();

        ctx.setCurrentChat(repo.getAllChats().getFirst());

        assertSame(canonical, ctx.currentChat(),
                "selecting a fresh copy of a cached chat must resolve to the canonical instance");
    }

    @Test
    public void deleteFiresOnlyForTheCurrentChat() {
        MemoryRepository repo = new MemoryRepository();
        repo.saveChat(new AIChat("current"));
        repo.saveChat(new AIChat("other"));
        AssistantContext ctx = new AssistantContext(null, repo);

        AtomicInteger events = new AtomicInteger();
        ctx.onChange("currentChat", e -> events.incrementAndGet());

        List<AIChat> all = ctx.getAllChats();
        AIChat current = all.get(0);
        AIChat other = all.get(1);
        ctx.setCurrentChat(current);
        assertEquals(1, events.get());

        ctx.deleteChat(other);
        assertEquals(1, events.get(), "deleting a non-current chat must not fire currentChat");
        assertSame(current, ctx.currentChat());

        AIChat duplicateOfCurrent = new AIChat(current.getTitle());
        duplicateOfCurrent.setGUID(current.getGUID());
        ctx.deleteChat(duplicateOfCurrent);
        assertEquals(2, events.get(), "deleting the current chat via a GUID-equal copy must fire");
        assertNull(ctx.currentChat());
    }

    @Test
    public void resetContextClearsSelectionAndCaches() {
        MemoryRepository repo = new MemoryRepository();
        AssistantContext ctx = contextWithChat(repo, "planning");
        AIChat cached = ctx.getAllChats().getFirst();
        ctx.setCurrentChat(cached);
        ctx.setCurrentModel("model-x");

        AtomicInteger events = new AtomicInteger();
        ctx.onChange("currentChat", e -> events.incrementAndGet());

        ctx.resetContext();

        assertEquals(1, events.get(), "reset must fire currentChat so the transcript clears");
        assertNull(ctx.currentChat());
        assertNull(ctx.getCurrentCredential());
        assertNull(ctx.getCurrentModel());
        assertNotSame(cached, ctx.getAllChats().getFirst(),
                "reset must drop the canonical cache — the next read is a fresh instance");
    }

    @Test
    public void captureAreasAreSessionStateAndClearOnReset() {
        MemoryRepository repo = new MemoryRepository();
        AssistantContext ctx = new AssistantContext(null, repo);

        CaptureArea area = new CaptureArea();
        area.setName("scanner grade panel");
        area.setBounds(new java.awt.Rectangle(120, 180, 640, 360));
        area.setDisplay("Display 1");

        assertTrue(area.isSelected(), "a new area must default to ticked");

        ctx.addCaptureArea(area);
        assertSame(area, ctx.getCaptureAreas().getFirst());

        ctx.resetContext();
        assertTrue(ctx.getCaptureAreas().isEmpty(), "reset must clear the session areas");

        ctx.addCaptureArea(area);
        ctx.removeCaptureArea(area);
        assertTrue(ctx.getCaptureAreas().isEmpty());
    }

    @Test
    public void capturesRoundTripThroughTheRepository() {
        MemoryRepository repo = new MemoryRepository();
        AssistantContext ctx = new AssistantContext(null, repo);

        AICapture capture = new AICapture();
        capture.setName("scanner grade panel 11:04");
        capture.setFromArea("scanner grade panel");
        AICapture saved = ctx.saveCapture(capture);

        assertNotNull(saved.getGUID());
        assertEquals(1, ctx.getAllCaptures().size());
        assertSame(saved, ctx.getCapture(saved.getGUID()));

        ctx.deleteCapture(saved);
        assertTrue(ctx.getAllCaptures().isEmpty());
    }

    @Test
    public void skillsMirrorTheChatCacheContract() {
        MemoryRepository repo = new MemoryRepository();
        AISkill stored = new AISkill();
        stored.setName("summarize");
        repo.saveSkill(stored);
        AssistantContext ctx = new AssistantContext(null, repo);

        AISkill first = ctx.getAllSkills().getFirst();
        assertSame(first, ctx.getAllSkills().getFirst());

        ctx.deleteSkill(first);
        assertTrue(ctx.getAllSkills().isEmpty(), "delete must remove the row from the repository");
    }
}
