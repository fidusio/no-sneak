package agent;

import agent.model.AIChat;

import java.util.List;

/**
 * Interface that can be used to store AIChats. To be implemented
 * as file system save, or database save
 */
public interface AIChatRepository {
    AIChat save(AIChat chat);

    AIChat getChat(String refID);

    List<AIChat> getAllChats();

    void delete(AIChat chat);
}
