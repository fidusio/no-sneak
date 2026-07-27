package io.xlogistx.nosneak.app.ui.assistant;

import io.xlogistx.nosneak.ai.AIRepository;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AISkill;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.util.SUS;

import java.util.List;

public class AssistantStorage implements AIRepository {
    private final APIDataStore<?, ?> ds;

    public AssistantStorage(APIDataStore<?, ?> ds) {
        this.ds = ds;
    }


    @Override
    public AIChat saveChat(AIChat chat) {
        return SUS.isNotEmpty(chat.getReferenceID()) ? ds.update(chat) : ds.insert(chat);
    }

    @Override
    public void deleteChat(AIChat chat) {
        ds.delete(chat, false);
    }

    @Override
    public AIChat getChat(String refID) {
        return ds.lookupByReferenceID(AIChat.NVC_AI_CHAT.getName(), refID);
    }

    @Override
    public List<AIChat> getAllChats() {
        return ds.search(AIChat.NVC_AI_CHAT, null);
    }

    @Override
    public AISkill saveSkill(AISkill skill) {
        return SUS.isNotEmpty(skill.getReferenceID()) ? ds.update(skill) : ds.insert(skill);
    }

    @Override
    public void deleteSkill(AISkill skill) {
        ds.delete(skill, false);
    }

    @Override
    public AISkill getSkill(String refID) {
        return ds.lookupByReferenceID(AISkill.NVC_AI_SKILL.getName(), refID);
    }

    @Override
    public List<AISkill> getAllSkills() {
        return ds.search(AISkill.NVC_AI_SKILL, null);
    }
}
