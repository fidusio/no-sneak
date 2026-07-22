package io.xlogistx.nosneak.app.mock.assistant;

import agent.AIChatRepository;
import agent.model.AIChat;

import java.util.List;

public class AssistantStorage implements AIChatRepository {

    @Override
    public AIChat save(AIChat chat) {
        return null;
    }

    @Override
    public AIChat getChat(String refID) {
        return null;
    }

    @Override
    public List<AIChat> getAllChats() {
        return List.of();
    }

    @Override
    public void delete(String refID) {

    }
}
