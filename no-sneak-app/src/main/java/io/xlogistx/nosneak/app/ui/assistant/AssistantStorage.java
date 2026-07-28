package io.xlogistx.nosneak.app.ui.assistant;

import io.xlogistx.nosneak.ai.AIRepository;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AISkill;
import io.xlogistx.nosneak.app.ui.utility.Session;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.util.SUS;

import java.util.List;

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
        if (SUS.isNotEmpty(chat.getReferenceID())) return ds.update(chat);
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
        if (SUS.isNotEmpty(skill.getReferenceID())) return ds.update(skill);
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
}