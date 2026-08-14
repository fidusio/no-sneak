package io.xlogistx.nosneak.app.ui.assistant;

import io.xlogistx.nosneak.ai.AIRepository;
import io.xlogistx.nosneak.ai.model.AICapture;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIProviderConfig;
import io.xlogistx.nosneak.ai.model.AISkill;
import io.xlogistx.nosneak.app.ui.utility.Session;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.util.SUS;

import java.util.List;

/**
 * Persistence for the assistant — chats, skills, provider configs and captures — over the same
 * encrypted H2 store the security layer uses, scoped to the signed-in subject.
 * <p>
 * <b>Every save is an upsert keyed on {@code getGUID()}</b>: non-empty updates, empty stamps the
 * owner and inserts (the store assigns the GUID). It must be {@code getGUID()} and never
 * {@code getReferenceID()} — that field is deprecated in zoxweb and the store never sets it, so
 * branching on it made every save an insert and duplicated the row on each edit.
 * <p>
 * Updates also stamp {@code lastTimeUpdated} explicitly, because the store only writes a timestamp
 * when the current one is 0 — it records creation and never advances "last updated" on its own.
 * The insert branch deliberately leaves it alone so a new row's created and updated times do not
 * land a millisecond apart.
 */
public class AssistantStorage implements AIRepository {
    private final APIDataStore<?, ?> ds;
    private final Session session;

    public AssistantStorage(Session session) {
        this.session = session;
        this.ds = session.getDomainSecurityManager().getDataStore();
    }

    private String owner() {
        return session.getSubjectGUID();
    }

    @Override
    public AIChat saveChat(AIChat chat) {
        if (SUS.isNotEmpty(chat.getGUID())) {
            chat.setLastTimeUpdated(System.currentTimeMillis());
            return ds.update(chat);
        }
        chat.setSubjectGUID(owner());
        return ds.insert(chat);
    }

    @Override
    public void deleteChat(AIChat chat) {
        ds.delete(chat, false);
    }

    @Override
    public AIChat getChat(String refID) {
        List<AIChat> found = ds.userSearchByID(owner(), AIChat.NVC_AI_CHAT, refID);
        return found.isEmpty() ? null : found.getFirst();
    }

    @Override
    public List<AIChat> getAllChats() {
        String o = owner();
        if (SUS.isEmpty(o)) return List.of();
        return ds.userSearch(owner(), AIChat.NVC_AI_CHAT, null);
    }

    @Override
    public AISkill saveSkill(AISkill skill) {
        if (SUS.isNotEmpty(skill.getGUID())) {
            skill.setLastTimeUpdated(System.currentTimeMillis());
            return ds.update(skill);
        }
        skill.setSubjectGUID(owner());
        return ds.insert(skill);
    }

    @Override
    public void deleteSkill(AISkill skill) {
        ds.delete(skill, false);
    }

    @Override
    public AISkill getSkill(String refID) {
        List<AISkill> found = ds.userSearchByID(owner(), AISkill.NVC_AI_SKILL, refID);
        return found.isEmpty() ? null : found.getFirst();
    }

    @Override
    public List<AISkill> getAllSkills() {
        String o = owner();
        if (SUS.isEmpty(o)) return List.of();
        return ds.userSearch(owner(), AISkill.NVC_AI_SKILL, null);
    }

    @Override
    public AIProviderConfig saveProviderConfig(AIProviderConfig config) {
        if (SUS.isNotEmpty(config.getGUID())) {
            config.setLastTimeUpdated(System.currentTimeMillis());
            return ds.update(config);
        }
        config.setSubjectGUID(owner());
        return ds.insert(config);
    }

    @Override
    public void deleteProviderConfig(AIProviderConfig config) {
        ds.delete(config, true);
    }

    @Override
    public AIProviderConfig getProviderConfig(String guid) {
        List<AIProviderConfig> found =
                ds.userSearchByID(owner(), AIProviderConfig.NVC_AI_PROVIDER_CONFIG, guid);
        return found.isEmpty() ? null : found.getFirst();
    }

    @Override
    public List<AIProviderConfig> getAllProviderConfigs() {
        String o = owner();
        if (SUS.isEmpty(o)) return List.of();
        return ds.userSearch(o, AIProviderConfig.NVC_AI_PROVIDER_CONFIG, null);
    }

    @Override
    public AICapture saveCapture(AICapture capture) {
        if (SUS.isNotEmpty(capture.getGUID())) {
            capture.setLastTimeUpdated(System.currentTimeMillis());
            return ds.update(capture);
        }
        capture.setSubjectGUID(owner());
        return ds.insert(capture);
    }

    @Override
    public void deleteCapture(AICapture capture) {
        ds.delete(capture, true);
    }

    @Override
    public AICapture getCapture(String guid) {
        List<AICapture> found =
                ds.userSearchByID(owner(), AICapture.NVC_AI_CAPTURE, guid);
        return found.isEmpty() ? null : found.getFirst();
    }

    /**
     * <b>A projected read — it deliberately omits {@code image}</b>, so rows carry a thumbnail and
     * no full-size PNG. Listing captures otherwise pulls every screenshot in the account into
     * memory to draw a list.
     * <p>
     * That creates an obligation on the save path: {@code saveCapture}'s update branch is
     * {@code ds.update}, which writes <i>every</i> column, so persisting a row that came from here
     * writes a null over the stored PNG. Anything that mutates a capture must re-read it through
     * {@link #getCapture(String)} first — and must handle that read returning null (signed out, or
     * deleted meanwhile) by bailing, <b>not</b> by falling back to the projected instance.
     */
    @Override
    public List<AICapture> getAllCaptures() {
        String o = owner();
        if (SUS.isEmpty(o)) return List.of();
        return ds.userSearch(o, AICapture.NVC_AI_CAPTURE, List.of("subject_guid", "name", "description", "from_area",
                "width", "height", "num_bytes", "thumbnail", "creation_ts"));
    }
}