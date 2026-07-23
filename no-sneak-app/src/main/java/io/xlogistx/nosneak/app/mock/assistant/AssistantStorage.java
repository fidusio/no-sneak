package io.xlogistx.nosneak.app.mock.assistant;

import agent.AIChatRepository;
import agent.model.AIChat;
import org.zoxweb.shared.api.APIDataStore;

import java.util.List;

public class AssistantStorage implements AIChatRepository {
    private final APIDataStore<?, ?> ds;
    public AssistantStorage(APIDataStore<?,?> ds) {this.ds = ds;}

    @Override
    public AIChat save(AIChat chat) {
        return ds.insert(chat);
    }

    @Override
    public AIChat getChat(String refID) {
       List<AIChat> found = ds.searchByID(AIChat.NVC_AI_CHAT, refID);
       return found.isEmpty() ? null : found.getFirst();
    }

    @Override
    public List<AIChat> getAllChats() {
        return ds.search(AIChat.NVC_AI_CHAT, null);
    }

    @Override
    public void delete(AIChat chat) {
        ds.delete(chat, false);
    }
}
